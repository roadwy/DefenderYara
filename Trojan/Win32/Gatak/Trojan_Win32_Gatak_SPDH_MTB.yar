
rule Trojan_Win32_Gatak_SPDH_MTB{
	meta:
		description = "Trojan:Win32/Gatak.SPDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 85 e8 0b 00 00 48 89 85 68 06 00 00 0f 10 85 d8 0b 00 00 0f 11 85 58 06 00 00 48 8b 45 c0 48 89 85 80 06 00 00 f3 0f 6f 45 b0 66 0f 7f 85 70 06 00 00 b9 02 00 00 00 31 d2 e8 ?? ?? ?? ?? 48 89 c6 48 83 f8 ff 0f 84 ?? ?? ?? ?? 48 8d 7d dc 41 b8 08 02 00 00 48 89 f9 31 d2 e8 ?? ?? ?? ?? 48 c7 45 b0 38 02 00 00 c7 45 b8 00 00 00 00 66 0f ef c0 f3 0f 7f 45 c0 f3 0f 7f 45 cc 48 8d 55 b0 48 89 f1 e8 ?? ?? ?? ?? 85 c0 0f 84 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}