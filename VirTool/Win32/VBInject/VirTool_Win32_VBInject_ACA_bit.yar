
rule VirTool_Win32_VBInject_ACA_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 00 8b 58 28 bf 4b 00 53 00 47 66 47 39 3b 75 ef 81 7b 04 56 00 42 00 75 } //1
		$a_03_1 = {bb 50 8b ec 83 90 02 20 83 c3 05 90 02 20 39 18 75 90 00 } //1
		$a_03_2 = {68 eb 0c 56 8d 90 02 20 5b 90 02 20 43 90 02 20 39 58 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}