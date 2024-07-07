
rule Backdoor_Win32_CobaltStrikeLoader_MS_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.MS!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 10 80 e0 0b 01 10 66 0f ef c1 0f 11 84 05 dc fc ff } //1
		$a_01_1 = {8a 88 e0 0b 01 10 80 f1 3e 88 8c 05 dc fc ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}