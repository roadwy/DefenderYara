
rule Trojan_Win32_FrostLizzard_D_dha{
	meta:
		description = "Trojan:Win32/FrostLizzard.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 4d f0 8b 55 e0 8b 75 c4 66 8b 14 56 66 89 14 41 8b 45 e0 83 c0 01 89 45 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_FrostLizzard_D_dha_2{
	meta:
		description = "Trojan:Win32/FrostLizzard.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 14 24 8b 55 3c 01 ea 8b 4c ca 78 8b 5c 0d 20 01 eb 8b 54 0d 1c 89 54 24 08 8b 4c 0d 24 89 4c 24 10 31 d2 90 90 90 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}