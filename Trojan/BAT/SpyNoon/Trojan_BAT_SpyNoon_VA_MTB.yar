
rule Trojan_BAT_SpyNoon_VA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_2 = {67 65 74 5f 4b 65 79 56 61 6c 75 65 } //01 00  get_KeyValue
		$a_81_3 = {73 65 74 5f 46 69 6c 65 4e 61 6d 65 } //01 00  set_FileName
		$a_81_4 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //01 00  get_KeyCode
		$a_81_5 = {24 33 32 62 37 61 39 38 34 2d 35 39 35 65 2d 34 34 61 62 2d 62 65 30 62 2d 35 36 34 32 64 32 64 34 30 62 65 65 } //00 00  $32b7a984-595e-44ab-be0b-5642d2d40bee
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_VA_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 6f 70 61 2e 61 6c 6d 61 63 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Ropa.almacen.resources
		$a_81_1 = {46 6f 72 6d 75 6c 61 72 69 6f 2e 4b 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Formulario.Kin.resources
		$a_81_2 = {46 6f 72 6d 75 6c 61 72 69 6f 41 6c 75 6d 6e 6f 2e 66 6f 72 6d 41 6c 75 6d 6e 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FormularioAlumno.formAlumno.resources
		$a_81_3 = {46 6f 72 6d 75 6c 61 72 69 6f 41 6c 75 6d 6e 6f 2e 61 63 65 70 74 61 72 41 6c 75 6d 6e 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FormularioAlumno.aceptarAlumno.resources
		$a_81_4 = {52 6f 70 61 2e 76 65 6e 74 61 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Ropa.ventas.resources
		$a_81_5 = {46 6f 72 6d 57 69 6e 64 6f 77 53 74 61 74 65 } //01 00  FormWindowState
		$a_81_6 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  GeneratedCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {41 73 73 65 6d 62 6c 79 50 72 6f 64 75 63 74 41 74 74 72 69 62 75 74 65 } //01 00  AssemblyProductAttribute
		$a_81_9 = {41 73 73 65 6d 62 6c 79 43 6f 70 79 72 69 67 68 74 41 74 74 72 69 62 75 74 65 } //01 00  AssemblyCopyrightAttribute
		$a_81_10 = {41 73 73 65 6d 62 6c 79 43 6f 6d 70 61 6e 79 41 74 74 72 69 62 75 74 65 } //01 00  AssemblyCompanyAttribute
		$a_81_11 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_81_12 = {44 65 71 75 65 75 65 } //01 00  Dequeue
		$a_81_13 = {45 6e 71 75 65 75 65 } //00 00  Enqueue
	condition:
		any of ($a_*)
 
}