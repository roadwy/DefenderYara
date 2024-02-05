
rule Trojan_Win32_Emotet_GLM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 15 04 84 40 00 31 c0 0b 05 90 01 04 c7 05 90 01 04 00 00 00 00 8b 00 01 05 04 84 40 00 8d 1d 04 84 40 00 81 2b 9f 00 00 00 72 42 ff 33 5b 83 7d fc 00 75 02 74 11 8d 05 83 51 a8 55 01 05 1c 84 40 00 e8 90 01 04 8d 0d 41 4f a8 55 31 c0 ff b0 1c 84 40 00 58 01 c1 89 0d 1c 84 40 00 eb 00 a1 1c 84 40 00 50 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}