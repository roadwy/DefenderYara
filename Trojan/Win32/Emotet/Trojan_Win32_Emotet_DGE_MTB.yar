
rule Trojan_Win32_Emotet_DGE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 40 83 c4 1c 89 85 90 1b 01 0f b6 94 15 90 01 04 30 50 ff 90 00 } //1
		$a_81_1 = {67 44 76 6e 32 37 78 58 46 61 44 36 6c 70 59 75 46 54 50 4c 5a 51 30 6f 38 4a 65 30 37 45 66 72 66 4e 63 44 42 56 } //1 gDvn27xXFaD6lpYuFTPLZQ0o8Je07EfrfNcDBV
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_DGE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DGE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc c1 e8 0d 83 e0 01 89 46 14 8b 45 10 89 46 1c 8b 45 14 89 46 20 8b 45 18 89 46 24 8b 45 1c 89 46 28 8b 45 d8 89 46 30 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}