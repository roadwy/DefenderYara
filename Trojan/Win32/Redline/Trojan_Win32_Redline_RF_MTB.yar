
rule Trojan_Win32_Redline_RF_MTB{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 18 33 c1 69 c8 90 01 04 33 f1 3b d5 7c df 90 09 0e 00 69 0c 93 90 01 04 42 69 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 bf 3c b6 22 f7 e2 c1 ea 03 0f be c2 8b 54 24 14 8a ca 6b c0 3b 2a c8 80 c1 33 30 4c 14 1c 42 89 54 24 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 88 90 01 04 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 68 90 01 04 6a 00 e8 90 02 30 28 1c 37 46 8b 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 f6 83 ec 18 c7 04 24 00 00 00 00 c7 44 24 04 00 00 00 00 89 54 24 08 89 4c 24 0c c7 44 24 10 00 00 00 00 c7 44 24 14 00 00 00 00 ff d0 89 c1 } //5
		$a_01_1 = {31 f6 83 ee 01 89 c2 01 f2 0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c1 88 c2 20 ca 30 c8 08 c2 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}