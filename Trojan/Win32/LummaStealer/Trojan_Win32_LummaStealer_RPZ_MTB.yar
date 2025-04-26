
rule Trojan_Win32_LummaStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 f6 17 8b c6 8b f3 33 db 33 f6 33 db 33 f6 8b f6 8b f3 33 f3 80 07 75 8b de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 89 45 f0 8b 4d e4 8b c6 d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f0 31 45 fc 8b 45 fc 29 45 e8 8b 45 d4 29 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 06 07 11 04 91 11 06 61 13 07 11 04 17 58 13 08 07 11 08 11 05 5d 91 13 09 20 00 01 00 00 13 0a 11 07 11 09 59 11 0a 58 11 0a 17 59 5f 13 0b 07 11 04 11 0b d2 9c 00 11 04 17 58 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}