
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace CSharpToWasm;

record Local(IType Type, string Name);

record ExpressionData(IType Type, WasmEmitter.Code[] Codes);

interface IType
{
    public WasmEmitter.Valtype Valtype { get; }
}

record Delegate(Signature[] Signatures) : IType
{
    public WasmEmitter.Valtype Valtype => throw new Exception("Cant get valtype from delegate");
    public override string ToString() => $"Delegate({Signatures[0].Name})";
}

record FloatType : IType
{
    public WasmEmitter.Valtype Valtype => WasmEmitter.Valtype.F32;
    public override string ToString() => "float";
}

record IntType : IType
{
    public WasmEmitter.Valtype Valtype => WasmEmitter.Valtype.I32;
    public override string ToString() => "int";
}

record VoidType : IType
{
    public WasmEmitter.Valtype Valtype => WasmEmitter.Valtype.Void;
    public override string ToString() => "void";
}

record Signature(string Name, IType[] Types, WasmEmitter.Code[] Codes, IType ReturnType);

record Cast(bool Implicit, IType From, IType To, WasmEmitter.Code[] Codes);

class FunctionData
{
    public readonly List<Local> locals = [];
    public readonly List<WasmEmitter.Code> codes = [];
}

static class Program
{
    static readonly FloatType floatType = new();
    static readonly IntType intType = new();
    static readonly VoidType voidType = new();
    static readonly List<Cast> casts = [];
    static readonly List<Signature> signatures = [];

    static bool HasAttribute(this MethodDeclarationSyntax method, string name)
    {
        return method.AttributeLists
                .SelectMany(al => al.Attributes)
                .Any(a => a.Name.ToString() == name);
    }

    static bool FullMatch(IType[] args, Signature signature)
    {
        if (signature.Types.Length != args.Length) return false;
        for (var i = 0; i < signature.Types.Length; i++)
        {
            if (signature.Types[i] != args[i]) return false;
        }
        return true;
    }

    static List<WasmEmitter.Code[]?>? CastMatch(IType[] args, Signature signature)
    {
        if (signature.Types.Length != args.Length) return null;
        List<WasmEmitter.Code[]?> castCodes = [];
        for (var i = 0; i < signature.Types.Length; i++)
        {
            if (signature.Types[i] != args[i])
            {
                var cast = casts.FirstOrDefault(c => c.Implicit && c.From == args[i] && c.To == signature.Types[i]);
                if (cast != null)
                {
                    castCodes.Add(cast.Codes);
                }
                else
                {
                    return null;
                }
            }
            else
            {
                castCodes.Add(null);
            }
        }
        return castCodes;
    }

    static ExpressionData Call(Signature[] signatures, ExpressionData[] args)
    {
        var argTypes = args.Select(a => a.Type).ToArray();
        foreach (var sig in signatures)
        {
            if (FullMatch(argTypes, sig))
            {
                List<WasmEmitter.Code> codes = [];
                foreach (var a in args)
                {
                    codes.AddRange(a.Codes);
                }
                codes.AddRange(sig.Codes);
                return new ExpressionData(sig.ReturnType, [.. codes]);
            }
        }
        foreach (var sig in signatures)
        {
            var castCodes = CastMatch(argTypes, sig);
            if (castCodes != null)
            {
                List<WasmEmitter.Code> codes = [];
                for (var i = 0; i < args.Length; i++)
                {
                    codes.AddRange(args[i].Codes);
                    var castCodesI = castCodes[i];
                    if (castCodesI != null)
                    {
                        codes.AddRange(castCodesI);
                    }
                }
                codes.AddRange(sig.Codes);
                return new ExpressionData(sig.ReturnType, [.. codes]);
            }
        }
        string strArgs = string.Join(", ", args.Select(a => a.Type.ToString()));
        throw new Exception($"Cant find signature with name: {signatures[0].Name} and args ({strArgs})");
    }

    static IType ToCSharpType(this TypeSyntax typeSyntax)
    {
        return typeSyntax.ToString() switch
        {
            "int" => intType,
            "float" => floatType,
            "void" => voidType,
            _ => throw new Exception($"Unexpected type: {typeSyntax}"),
        };
    }

    static ExpressionData EmitExpression(FunctionData fd, ExpressionSyntax expressionSyntax)
    {
        if (expressionSyntax is InvocationExpressionSyntax invocationExpressionSyntax)
        {
            var args = invocationExpressionSyntax.ArgumentList.Arguments
                .Select(a => EmitExpression(fd, a.Expression)).ToArray();
            var nameData = EmitExpression(fd, invocationExpressionSyntax.Expression);
            if (nameData.Type is Delegate del)
            {
                return Call(del.Signatures, args);
            }
            else
            {
                throw new Exception("expecting name to be identifier");
            }
        }
        else if (expressionSyntax is IdentifierNameSyntax identifierNameSyntax)
        {
            var local = fd.locals.FirstOrDefault(l => l.Name == identifierNameSyntax.Identifier.ValueText);
            if (local == null)
            {
                var sigs = signatures.Where(s => s.Name == identifierNameSyntax.Identifier.ValueText).ToArray();
                return new (new Delegate(sigs), []);
            }
            else
            {
                return new(local.Type, [new(WasmEmitter.Opcode.get_local, local.Name)]);
            }
        }
        else if (expressionSyntax is BinaryExpressionSyntax binaryExpressionSyntax)
        {
            var left = EmitExpression(fd, binaryExpressionSyntax.Left);
            var right = EmitExpression(fd, binaryExpressionSyntax.Right);
            var sigs = signatures.Where(s => s.Name == binaryExpressionSyntax.OperatorToken.ToString()).ToArray();
            return Call(sigs, [left, right]);
        }
        else if (expressionSyntax is LiteralExpressionSyntax literalExpressionSyntax)
        {
            if (literalExpressionSyntax.Token.Value is int intValue)
            {
                return new (intType, [new(WasmEmitter.Opcode.i32_const, intValue.ToString())]);
            }
            else if (literalExpressionSyntax.Token.Value is float floatValue)
            {
                return new (floatType, [new(WasmEmitter.Opcode.f32_const, floatValue.ToString())]);
            }
            else
            {
                throw new Exception("Unexpected type: " + literalExpressionSyntax.Token.Value?.GetType().Name);
            }
        }
        else
        {
            throw new Exception(expressionSyntax.GetType().Name);
        }
    }

    static void EmitVariable(FunctionData fd, VariableDeclaratorSyntax variableDeclaratorSyntax, TypeSyntax typeSyntax)
    {
        var name = variableDeclaratorSyntax.Identifier.ValueText;
        if (variableDeclaratorSyntax.Initializer != null)
        {
            var exprData = EmitExpression(fd, variableDeclaratorSyntax.Initializer.Value);
            if (typeSyntax.ToString() == "var")
            {
                fd.codes.AddRange(exprData.Codes);
                fd.codes.Add(new(WasmEmitter.Opcode.set_local, name));
                fd.locals.Add(new(exprData.Type, name));
            }
            else
            {
                var type = typeSyntax.ToCSharpType();
                if (type == exprData.Type)
                {
                    fd.codes.AddRange(exprData.Codes);
                    fd.codes.Add(new(WasmEmitter.Opcode.set_local, name));
                    fd.locals.Add(new(type, name));
                }
                else
                {
                    var implicitCast = casts.FirstOrDefault(c => c.Implicit && c.From == exprData.Type && c.To == type);
                    if (implicitCast == null)
                    {
                        throw new Exception("Cant cast expression to localvariable");
                    }
                    else
                    {
                        fd.codes.AddRange(exprData.Codes);
                        fd.codes.AddRange(implicitCast.Codes);
                        fd.codes.Add(new(WasmEmitter.Opcode.set_local, name));
                        fd.locals.Add(new(type, name));
                    }
                }
            }
        }
        else
        {
            var type = typeSyntax.ToCSharpType();
            fd.locals.Add(new(type, name));
        }
    }

    static void EmitLocalDeclaration(FunctionData fd, VariableDeclarationSyntax variableDeclarationSyntax)
    {
        var typeSyntax = variableDeclarationSyntax.Type;
        foreach (var v in variableDeclarationSyntax.Variables)
        {
            EmitVariable(fd, v, typeSyntax);
        }
    }

    static void EmitStatement(FunctionData fd, StatementSyntax statementSyntax)
    {
        if (statementSyntax is ExpressionStatementSyntax expressionStatementSyntax)
        {
            var exprData = EmitExpression(fd, expressionStatementSyntax.Expression);
            fd.codes.AddRange(exprData.Codes);
            if (exprData.Type is not VoidType)
            {
                fd.codes.Add(new(WasmEmitter.Opcode.drop));
            }
        }
        else if (statementSyntax is LocalDeclarationStatementSyntax localDeclarationStatementSyntax)
        {
            EmitLocalDeclaration(fd, localDeclarationStatementSyntax.Declaration);
        }
        else
        {
            throw new Exception(statementSyntax.GetType().Name);
        }
    }

    static WasmEmitter.Function EmitFunction(MethodDeclarationSyntax methodDeclarationSyntax, int i)
    {
        var functionData = new FunctionData();
        foreach (var s in methodDeclarationSyntax.Body!.Statements)
        {
            EmitStatement(functionData, s);
        }
        bool export = methodDeclarationSyntax.HasAttribute("export");
        var name = GetName(methodDeclarationSyntax.Identifier.ValueText, i);
        var returnType = methodDeclarationSyntax.ReturnType.ToCSharpType().Valtype;
        var parameters = methodDeclarationSyntax.ParameterList.Parameters
            .Select(p => new WasmEmitter.Parameter(p.Type!.ToCSharpType().Valtype, p.Identifier.ValueText))
            .ToArray();
        var locals = functionData.locals.Select(l => new WasmEmitter.Local(l.Type.Valtype, l.Name)).ToArray();
        return new(export, name, returnType, parameters, locals, [.. functionData.codes]);
    }

    static string GetName(string name, int i)
    {
        if(name == "Main")
        {
            return name;
        }
        return "_" + i.ToString() + "_" + name;
    }

    static void Main()
    {
        casts.Add(new Cast(true, intType, floatType, [new(WasmEmitter.Opcode.f32_convert_i32_s)]));

        signatures.Add(new("+", [intType, intType], [new(WasmEmitter.Opcode.i32_add)], intType));
        signatures.Add(new("-", [intType, intType], [new(WasmEmitter.Opcode.i32_sub)], intType));
        signatures.Add(new("*", [intType, intType], [new(WasmEmitter.Opcode.i32_mul)], intType));
        signatures.Add(new("/", [intType, intType], [new(WasmEmitter.Opcode.i32_div_s)], intType));

        signatures.Add(new("+", [floatType, floatType], [new(WasmEmitter.Opcode.f32_add)], floatType));
        signatures.Add(new("-", [floatType, floatType], [new(WasmEmitter.Opcode.f32_sub)], floatType));
        signatures.Add(new("*", [floatType, floatType], [new(WasmEmitter.Opcode.f32_mul)], floatType));
        signatures.Add(new("/", [floatType, floatType], [new(WasmEmitter.Opcode.f32_div)], floatType));

        SyntaxTree tree = CSharpSyntaxTree.ParseText(File.ReadAllText("code.txt"));
        var root = (CompilationUnitSyntax)tree.GetRoot();

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>().ToArray();

        for(var i = 0; i < methods.Length; i++)
        {
            var m = methods[i];
            var name = m.Identifier.ValueText;
            var newName = GetName(name, i);
            var returnType = m.ReturnType.ToCSharpType();
            var types = m.ParameterList.Parameters.Select(p => p.Type!.ToCSharpType()).ToArray();
            signatures.Add(new(m.Identifier.ValueText, types, [new(WasmEmitter.Opcode.call, newName)], returnType));
        }

        List<WasmEmitter.ImportFunction> importFunctions = [];
        List<WasmEmitter.Function> functions = [];
        for(var i = 0; i < methods.Length; i++)
        {
            var m = methods[i];
            if (m.HasAttribute("import"))
            {
                var name = GetName(m.Identifier.ValueText, i);
                var returnType = m.ReturnType.ToCSharpType().Valtype;
                var parameters = m.ParameterList.Parameters
                    .Select(p => new WasmEmitter.Parameter(p.Type!.ToCSharpType().Valtype, p.Identifier.ValueText))
                    .ToArray();
                importFunctions.Add(new(name, returnType, parameters, m.Body!.ToFullString()));
            }
            else
            {
                functions.Add(EmitFunction(m, i));
            }
        }

        var html = WasmEmitter.WasmEmitter.Emit([.. functions], [.. importFunctions], true);
        File.WriteAllText("index.html", html);
    }
}