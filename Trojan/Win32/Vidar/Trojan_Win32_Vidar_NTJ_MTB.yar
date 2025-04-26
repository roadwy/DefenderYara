
rule Trojan_Win32_Vidar_NTJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 5c 0c 3c 0f b6 44 2c 3c 8b 4c 24 ?? 03 c7 8b 5c 24 14 0f b6 c0 8a 44 04 3c 30 04 19 8b 44 24 ?? 2b c6 83 e0 f8 50 56 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}