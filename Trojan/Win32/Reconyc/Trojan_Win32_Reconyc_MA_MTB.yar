
rule Trojan_Win32_Reconyc_MA_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 56 29 c9 89 8d f0 fe ff ff 8b da 50 5e 33 c0 55 68 90 01 04 64 ff 30 64 89 20 53 58 e8 90 01 04 8d 45 fc 50 56 6a 00 e8 90 00 } //5
		$a_01_1 = {ff 25 d0 c1 44 00 8b c0 ff 25 48 c2 44 00 8b c0 ff 25 44 c2 44 00 8b c0 ff 25 40 c2 44 00 8b c0 ff 25 cc c1 44 00 8b c0 ff 25 c8 c1 44 00 8b c0 ff 25 58 c2 44 00 8b c0 ff 25 54 } //5
		$a_01_2 = {dc b5 44 00 89 01 89 0d dc b5 44 00 29 d2 8b c2 03 c0 8d 44 c1 04 8b 1e 89 18 89 06 42 83 fa 64 75 ec 8b 06 8b 10 89 16 5e 5b c3 90 89 00 89 40 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}