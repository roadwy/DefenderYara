
rule Backdoor_Win32_Androm_GXZ_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6a 40 68 78 da 04 00 53 ff 15 } //5
		$a_03_1 = {8b ca 83 e1 03 f3 a4 8b 7b 04 8b ?? ?? ?? ?? ?? 03 fd 89 7b 04 ff d6 6a 0a ff d6 6a 0a ff d6 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}