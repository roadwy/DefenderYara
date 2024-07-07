
rule Trojan_Win32_NukeSped_SRP_MTB{
	meta:
		description = "Trojan:Win32/NukeSped.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 83 c2 01 89 55 f0 81 7d f0 00 01 00 00 73 4b 8b 45 e8 03 45 f0 0f b6 00 03 45 dc 8b 4d f8 03 4d f0 0f b6 11 03 c2 33 d2 b9 00 01 00 00 f7 f1 89 55 dc 8b 55 e8 03 55 f0 8a 02 88 45 ef 8b 4d e8 03 4d f0 8b 55 e8 03 55 dc 8a 02 88 01 8b 4d e8 03 4d dc 8a 55 ef 88 11 eb a3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}