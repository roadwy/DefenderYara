
rule Trojan_Win32_Ekstak_RA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 d8 67 fb ff eb 0d 8b 75 fc e8 ce 67 fb ff eb 03 8b 75 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c2 d1 f8 03 c1 8b 4d f0 89 86 c4 00 00 00 8b 45 f8 2b c1 2b 45 dc 99 2b c2 d1 f8 03 c1 89 86 c8 00 cc cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 68 ?? 30 65 00 6a 01 6a 00 ff 15 ?? f3 64 00 8b f0 85 f6 74 2a ff 15 ?? f3 64 00 3d b7 00 00 00 75 13 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RA_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 fb ff 8b f0 e9 90 09 04 00 56 57 e8 } //4
		$a_01_1 = {40 00 00 40 5f 62 63 6f 72 65 } //1 @䀀扟潣敲
		$a_01_2 = {43 00 61 00 74 00 61 00 6c 00 6f 00 67 00 69 00 63 00 20 00 42 00 6f 00 6f 00 6b 00 20 00 4c 00 69 00 73 00 74 00 } //1 Catalogic Book List
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}