
rule Trojan_Win32_PSWStealer_GRM_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b c6 83 e8 65 33 05 e8 0e 48 00 83 e8 38 81 c0 bb c8 63 62 2b c7 81 f0 2a a4 3a bf 68 09 54 46 00 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}