
rule VirTool_WinNT_Rootkitdrv_KI{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 4e 61 6d 65 } //1 ObReferenceObjectByName
		$a_00_1 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 43 00 } //1 \Driver\ProtectedC
		$a_01_2 = {81 38 59 68 e8 03 } //1
		$a_01_3 = {81 78 04 00 00 e8 0e } //1
		$a_03_4 = {8b 0c b3 0b c9 74 90 01 01 8b 79 04 66 8b 07 66 83 f8 03 75 90 01 01 8b 47 10 0b c0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}