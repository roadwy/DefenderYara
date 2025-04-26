
rule Trojan_Win32_PSWStealer_MP_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 93 33 85 40 fc ff ff 88 45 93 8b 8d fc fd ff ff 8b 11 8b 8d f0 fd ff ff d3 e2 89 95 e4 fd ff ff 8b 45 e4 8b 8d 68 fc ff ff 8b 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}