
rule Trojan_Win32_PSWStealer_SDS_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.SDS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 d0 4c 8d 64 24 04 c0 c8 4e d2 e2 8b 45 08 0f 9a c2 8b 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}