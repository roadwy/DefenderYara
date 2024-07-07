
rule VirTool_Win32_DelfInject_DQ_bit{
	meta:
		description = "VirTool:Win32/DelfInject.DQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 40 00 00 00 ba 9d 53 00 00 a1 90 01 02 48 00 ff 15 90 01 02 48 00 33 db a1 90 01 02 48 00 03 c3 8a 00 90 90 34 a6 8b 15 60 90 01 02 00 03 d3 88 02 90 90 43 81 fb 90 01 03 00 75 90 00 } //1
		$a_03_1 = {bb 3a 02 00 00 a1 90 01 02 48 00 03 c3 a3 90 01 02 48 00 90 90 90 90 90 90 ff 35 90 01 02 48 00 c3 90 00 } //1
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}