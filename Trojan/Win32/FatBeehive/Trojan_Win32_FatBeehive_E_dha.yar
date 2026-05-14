
rule Trojan_Win32_FatBeehive_E_dha{
	meta:
		description = "Trojan:Win32/FatBeehive.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 01 84 c0 75 03 8b c2 [0-01] 0f be c0 33 c2 69 d0 a4 61 13 03 41 } //1
		$a_03_1 = {8b 3c b0 8a 04 1f 03 fb 84 c0 75 [0-01] b8 1a 54 32 24 eb 1c 0f be c0 8d 4f 01 35 1a 54 32 24 69 d0 a4 61 13 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}