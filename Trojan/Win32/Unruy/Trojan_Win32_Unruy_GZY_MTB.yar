
rule Trojan_Win32_Unruy_GZY_MTB{
	meta:
		description = "Trojan:Win32/Unruy.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0e 34 6b c0 12 fc 4e 46 09 27 } //5
		$a_03_1 = {8a 66 7b f3 91 ba ?? ?? ?? ?? 34 e9 13 26 01 56 7b 1b 70 71 30 3a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}