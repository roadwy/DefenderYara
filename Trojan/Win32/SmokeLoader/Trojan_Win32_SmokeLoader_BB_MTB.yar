
rule Trojan_Win32_SmokeLoader_BB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 dc fd ff ff 0f b6 b4 05 f8 fe ff ff 8b 45 08 8b 8d e4 fd ff ff 0f b6 14 08 31 f2 88 14 08 8b 85 e4 fd ff ff 83 c0 01 89 85 e4 fd ff ff e9 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}