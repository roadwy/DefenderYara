
rule Trojan_Win32_Stealc_GKA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 4c 05 90 01 01 c1 f9 02 03 d1 8b 45 e8 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 ba 90 01 04 6b c2 90 01 01 0f be 4c 90 01 01 f4 83 f9 90 01 01 0f 84 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}