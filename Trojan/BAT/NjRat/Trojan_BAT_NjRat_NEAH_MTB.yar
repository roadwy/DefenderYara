
rule Trojan_BAT_NjRat_NEAH_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f ?? 00 00 0a 2b ee 28 ?? 00 00 0a 2b eb } //10
		$a_03_1 = {2a 2b 18 14 2b 18 16 2d eb 2a 28 ?? 00 00 06 2b df 28 ?? 00 00 0a 2b da 0a 2b d9 06 2b e5 6f ?? 00 00 0a 2b e1 } //10
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 30 2e 34 38 39 32 } //5 Powered by SmartAssembly 8.1.0.4892
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=25
 
}