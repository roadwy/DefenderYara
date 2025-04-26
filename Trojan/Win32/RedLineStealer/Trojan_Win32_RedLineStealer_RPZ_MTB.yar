
rule Trojan_Win32_RedLineStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db b8 11 00 00 00 83 c0 1f 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 68 00 10 00 00 8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 02 f6 bf 50 eb 02 8d 43 e8 1a 00 00 00 eb 04 be da 68 17 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 04 8d 4d dc 51 8b 8b a4 00 00 00 83 c1 08 51 ff 75 cc ff d0 6a 40 68 00 30 00 00 ff b7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}