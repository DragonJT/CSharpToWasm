namespace WasmEmitter;
using System.Text;

enum Opcode
{
    block = 0x02,
    loop = 0x03,
    br = 0x0c,
    br_if = 0x0d,
    end = 0x0b,
    ret = 0x0f,
    call = 0x10,
    drop = 0x1a,
    get_local = 0x20,
    set_local = 0x21,
    i32_store_8 = 0x3a,
    i32_const = 0x41,
    f32_const = 0x43,
    i32_eqz = 0x45,
    i32_eq = 0x46,
    f32_eq = 0x5b,
    f32_lt = 0x5d,
    f32_gt = 0x5e,
    i32_and = 0x71,
    f32_add = 0x92,
    f32_sub = 0x93,
    f32_mul = 0x94,
    f32_div = 0x95,
    f32_neg = 0x8c,
    i32_trunc_f32_s = 0xa8,
    f32_load = 0x2a,
    f32_store = 0x38,
    i32_store = 0x36,
    i32_load = 0x28,
    i32_mul = 0x6c,
    i32_add = 0x6a,
    i32_sub = 0x6b,
    i32_div_s = 0x6d,
    f32_convert_i32_s = 0xb2,
    i32_lt_s = 0x48,
    i32_gt_s = 0x4a,
    @if = 0x04,
}

enum SectionType
{
    Custom = 0,
    Type = 1,
    Import = 2,
    Func = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11
}

enum Valtype
{
    Void = 0x40,
    I32 = 0x7f,
    F32 = 0x7d
}

enum ExportType
{
    Func = 0x00,
    Table = 0x01,
    Mem = 0x02,
    Global = 0x03
}

record Code(Opcode Opcode, string Value = "");

record Parameter(Valtype Type, string Name);

record Local(Valtype Type, string Name);

record ImportFunction(string Name, Valtype ReturnType, Parameter[] Parameters, string Code);

record Function(bool Export, string Name, Valtype ReturnType, Parameter[] Parameters, Local[] Locals, Code[] Codes);

static class Printer
{
    public static string PrintParameters(Parameter[] parameters, bool printType)
    {
        string result = "(";
        for (var i = 0; i < parameters.Length; i++)
        {
            if (printType) result += parameters[i].Type + " ";
            result += parameters[i].Name;
            if (i < parameters.Length - 1)
            {
                result += ", ";
            }
        }
        result += ")";
        return result;
    }

    public static string PrintFunction(this Function f)
    {
        StringBuilder builder = new();
        if (f.Export) builder.Append("export ");
        builder.AppendLine(f.ReturnType + " " + f.Name + PrintParameters(f.Parameters, true));
        builder.AppendLine("{");
        foreach (var i in f.Codes)
        {
            builder.AppendLine("    " + i.Opcode + " - " + i.Value);
        }
        builder.AppendLine("}");
        return builder.ToString();
    }


    public static string PrintImportFunction(this ImportFunction f)
    {
        StringBuilder builder = new();
        builder.AppendLine("import " + f.Name + PrintParameters(f.Parameters, true));
        builder.Append('{');
        builder.AppendLine(f.Code);
        builder.AppendLine("}");
        return builder.ToString();
    }
}

static class WasmEmitter
{
    static Valtype GetValtype(string type)
    {
        return type switch
        {
            "int" => Valtype.I32,
            "float" => Valtype.F32,
            "void" => Valtype.Void,
            _ => throw new Exception($"Unexpected type :{type}"),
        };
    }

    public const byte emptyArray = 0x0;
    public const byte functionType = 0x60;

    public static byte[] MagicModuleHeader => [0x00, 0x61, 0x73, 0x6d];

    public static byte[] ModuleVersion => [0x01, 0x00, 0x00, 0x00];

    public static byte[] Ieee754(float value)
    {
        return BitConverter.GetBytes(value);
    }

    public static byte[] SignedLEB128(int value)
    {
        List<byte> bytes = [];
        bool more = true;

        while (more)
        {
            byte chunk = (byte)(value & 0x7fL); // extract a 7-bit chunk
            value >>= 7;

            bool signBitSet = (chunk & 0x40) != 0; // sign bit is the msb of a 7-bit byte, so 0x40
            more = !((value == 0 && !signBitSet) || (value == -1 && signBitSet));
            if (more) { chunk |= 0x80; } // set msb marker that more bytes are coming

            bytes.Add(chunk);
        }
        return bytes.ToArray();
    }

    public static byte[] UnsignedLEB128(uint value)
    {
        List<byte> bytes = [];
        do
        {
            byte byteValue = (byte)(value & 0x7F); // Extract 7 bits
            value >>= 7; // Shift right by 7 bits

            if (value != 0)
                byteValue |= 0x80; // Set the high bit to indicate more bytes

            bytes.Add(byteValue);
        }
        while (value != 0);
        return [.. bytes];
    }

    public static byte[] String(string value)
    {
        List<byte> bytes = [.. UnsignedLEB128((uint)value.Length)];
        foreach (var v in value)
        {
            bytes.Add((byte)v);
        }
        return [.. bytes];
    }

    public static byte[] Vector(byte[][] vector)
    {
        return [.. UnsignedLEB128((uint)vector.Length), .. vector.SelectMany(b => b).ToArray()];
    }

    public static byte[] Vector(byte[] vector)
    {
        return [.. UnsignedLEB128((uint)vector.Length), .. vector];
    }

    public static byte[] Local(uint count, Valtype valtype)
    {
        return [.. UnsignedLEB128(count), (byte)valtype];
    }

    public static byte[] Section(SectionType section, byte[][] bytes)
    {
        return [(byte)section, .. Vector(Vector(bytes))];
    }

    public static byte[] Return(Valtype type)
    {
        if (type == Valtype.Void)
        {
            return [emptyArray];
        }
        else
        {
            return Vector([(byte)type]);
        }
    }

    static byte[] EmitCode(Function f, Dictionary<string, uint> functionIDs)
    {
        Dictionary<string, uint> localIDs = [];
        uint vid = 0;
        foreach (var p in f.Parameters)
        {
            localIDs.Add(p.Name, vid);
            vid++;
        }

        Dictionary<Valtype, List<Local>> locals = [];
        foreach (var l in f.Locals)
        {
            if (locals.TryGetValue(l.Type, out List<Local>? localsOfType))
            {
                localsOfType.Add(l);
            }
            else
            {
                locals.Add(l.Type, [l]);
            }
        }

        List<byte[]> localBytes = [];
        foreach (var key in locals.Keys)
        {
            var localsOfType = locals[key];
            foreach (var v in localsOfType)
            {
                localIDs.Add(v.Name, vid);
                vid++;
            }
            localBytes.Add(Local((uint)localsOfType.Count, key));
        }

        List<byte> codeBytes = [];
        foreach (var instruction in f.Codes)
        {
            if (instruction.Opcode == Opcode.i32_const)
            {
                codeBytes.AddRange([(byte)Opcode.i32_const, .. SignedLEB128(int.Parse(instruction.Value))]);
            }
            else if (instruction.Opcode == Opcode.f32_const)
            {
                codeBytes.AddRange([(byte)Opcode.f32_const, .. Ieee754(float.Parse(instruction.Value))]);
            }
            else if (instruction.Opcode == Opcode.get_local)
            {
                var id = localIDs[instruction.Value];
                codeBytes.AddRange([(byte)Opcode.get_local, .. UnsignedLEB128(id)]);
            }
            else if (instruction.Opcode == Opcode.set_local)
            {
                var id = localIDs[instruction.Value];
                codeBytes.AddRange([(byte)Opcode.set_local, .. UnsignedLEB128(id)]);
            }
            else if (instruction.Opcode == Opcode.call)
            {
                var id = functionIDs[instruction.Value!];
                codeBytes.AddRange([(byte)Opcode.call, .. UnsignedLEB128(id)]);
            }
            else if (instruction.Opcode == Opcode.@if)
            {
                codeBytes.AddRange([(byte)Opcode.@if, (byte)GetValtype(instruction.Value)]);
            }
            else if (instruction.Opcode == Opcode.block)
            {
                codeBytes.AddRange([(byte)Opcode.block, (byte)GetValtype(instruction.Value)]);
            }
            else if (instruction.Opcode == Opcode.loop)
            {
                codeBytes.AddRange([(byte)Opcode.loop, (byte)GetValtype(instruction.Value)]);
            }
            else if (instruction.Opcode == Opcode.br)
            {
                var id = uint.Parse(instruction.Value);
                codeBytes.AddRange([(byte)Opcode.br, .. UnsignedLEB128(id)]);
            }
            else if (instruction.Opcode == Opcode.i32_load)
            {
                codeBytes.AddRange([(byte)Opcode.i32_load, 0x00, 0x00]); //align, offset
            }
            else if (instruction.Opcode == Opcode.i32_store)
            {
                codeBytes.AddRange([(byte)Opcode.i32_store, 0x00, 0x00]); //align, offset
            }
            else if(instruction.Opcode == Opcode.br_if)
            {
                var id = uint.Parse(instruction.Value);
                codeBytes.AddRange([(byte)Opcode.br_if, .. UnsignedLEB128(id)]);
            }
            else
            {
                if (instruction.Value != "") throw new Exception($"{instruction.Opcode} ignores value {instruction.Value}.");
                codeBytes.Add((byte)instruction.Opcode);
            }
        }
        return Vector([.. Vector([.. localBytes]), .. codeBytes, (byte)Opcode.end]);
    }

    public static string Emit(Function[] functions, ImportFunction[] importFunctions, bool memory)
    {
        //foreach (var f in importFunctions) Console.WriteLine(Printer.PrintImportFunction(f));
        //foreach (var f in functions) Console.WriteLine(Printer.PrintFunction(f));
        
        Dictionary<string, uint> functionIDs = [];
        foreach (var f in importFunctions)
        {
            functionIDs.Add(f.Name, (uint)functionIDs.Count);
        }
        foreach (var f in functions)
        {
            functionIDs.Add(f.Name, (uint)functionIDs.Count);
        }

        List<byte[]> codeSection = [];
        foreach (var f in functions)
        {
            codeSection.Add(EmitCode(f, functionIDs));
        }

        List<byte[]> importSection = [];
        foreach (var f in importFunctions)
        {
            importSection.Add([
                ..String("env"),
                ..String(f.Name),
                (byte)ExportType.Func,
                ..UnsignedLEB128(functionIDs[f.Name])
            ]);
        }

        if (memory)
        {
            importSection.Add([
                ..String("env"),
                ..String("memory"),
                (byte)ExportType.Mem,
                /* limits https://webassembly.github.io/spec/core/binary/types.html#limits -
                indicates a min memory size of one page */
                0x00,
                ..UnsignedLEB128(10),
            ]);
        }

        List<byte[]> typeSection = [];
        foreach (var f in importFunctions)
        {
            typeSection.Add([
                functionType,
                ..Vector(f.Parameters.Select(p=>(byte)p.Type).ToArray()),
                ..Return(f.ReturnType)
            ]);
        }
        foreach (var f in functions)
        {
            typeSection.Add([
                functionType,
                ..Vector(f.Parameters.Select(p=>(byte)p.Type).ToArray()),
                ..Return(f.ReturnType)
            ]);
        }

        List<byte[]> funcSection = [];
        foreach (var f in functions)
        {
            funcSection.Add(UnsignedLEB128(functionIDs[f.Name]));
        }

        List<byte[]> exportSection = [];
        foreach (var f in functions)
        {
            exportSection.Add([.. String(f.Name), (byte)ExportType.Func, .. UnsignedLEB128(functionIDs[f.Name])]);
        }

        byte[] wasm = [
            .. MagicModuleHeader,
            .. ModuleVersion,
            .. Section(SectionType.Type, [..typeSection]),
            .. Section(SectionType.Import, [.. importSection]),
            .. Section(SectionType.Func, [..funcSection]),
            .. Section(SectionType.Export, [..exportSection]),
            .. Section(SectionType.Code, [..codeSection])];

        //File.WriteAllBytes("run.wasm", wasm);

        StringBuilder importString = new();
        foreach (var f in importFunctions)
        {
            importString.AppendLine("imports.env." + f.Name + "=function" + Printer.PrintParameters(f.Parameters, false));
            importString.Append('{');
            importString.AppendLine(f.Code);
            importString.AppendLine("}");
        }
        if (memory)
        {
            importString.AppendLine("imports.env.memory = new WebAssembly.Memory({ initial: 10, maximum: 10 });");
        }
        string wasmString = string.Join(",", wasm.Select(b => "0x" + b.ToString("X2")));
        var html = @"
<!DOCTYPE html>
<html>
<head>
  <title>WebAssembly Example</title>
</head>
<body>
  <script>
const wasmBytecode = new Uint8Array([
" + wasmString +
@"]);
var globals = {};
var imports = {};
var exports;
imports.env = {};
" +
importString
+ @"
WebAssembly.instantiate(wasmBytecode, imports)
  .then(module => {
    exports = module.instance.exports;
    console.log(module.instance.exports.Main());
  })
  .catch(error => {
    console.error('Error:', error);
  });
  </script>
</body>
</html>";
        return html;
    }
}