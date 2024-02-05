
rule Trojan_Win32_Emotet_GMF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {d3 e6 89 44 24 0c 8b 44 24 0c 8b c8 c1 e1 05 03 c8 89 4c 24 0c 81 74 24 0c 10 a0 74 d8 0f b6 4c 24 0c 8b 54 24 10 0f be 43 ff 89 44 24 10 01 74 24 10 d3 e2 01 54 24 10 29 7c 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}