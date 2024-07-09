
rule Trojan_BAT_AveMaria_NEEV_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 14 2b 19 2b 1e 17 2d 06 26 16 2d 04 de 22 2b 1a 19 2c ec 2b f4 28 ?? 00 00 06 2b e5 28 ?? 00 00 2b 2b e0 28 ?? 00 00 2b 2b db 0a 2b e3 } //10
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 32 2e 34 39 37 35 } //2 Powered by SmartAssembly 8.1.2.4975
		$a_01_2 = {49 6e 76 6f 6b 65 } //2 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}