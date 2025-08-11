
rule Trojan_Win32_Fragtor_LM_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 95 e7 ef ff ff 2a d0 8b 85 18 f0 ff ff 02 d1 30 17 83 c0 21 3b 85 14 f0 ff ff 7e ?? ff 8d 0c f0 ff ff 3b c6 7c ?? 8b d6 d1 ea 2b d6 03 d0 8d 7c 0a 05 eb } //15
		$a_03_1 = {83 fa 67 75 ?? 8d 4c 00 01 8b d0 d3 e2 8d 48 01 85 c9 7e ?? 8d 49 00 0f af d0 03 d2 03 d2 03 d2 49 75 f4 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}