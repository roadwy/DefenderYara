
rule Trojan_Win32_Dridex_AS_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 2b 94 24 9e 00 00 00 88 cf 08 fb 88 9c 24 d6 00 00 00 66 89 94 24 9e } //0a 00 
		$a_01_1 = {8a 84 24 d6 00 00 00 f6 d8 8b 8c 24 e0 00 00 00 88 84 24 d6 00 00 00 8a 84 24 d7 00 00 00 f6 d8 88 84 24 d6 } //00 00 
	condition:
		any of ($a_*)
 
}