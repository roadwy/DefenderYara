
rule Backdoor_Win32_Androm_GXA_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 8b 5c 24 90 01 01 55 8b 6c 24 20 56 55 ff 15 90 01 04 53 8b f0 66 c7 44 24 90 01 01 02 00 ff 15 90 00 } //5
		$a_01_1 = {8b fb 6a 40 68 78 da 04 00 f3 a5 53 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}