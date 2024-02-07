
rule Trojan_BAT_Injuke_AADI_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 49 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 15 2d 09 26 12 00 18 2d 06 26 de 0d 0a 2b f5 28 90 01 01 00 00 06 2b f4 26 de 00 06 2c cf 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00  ReadAsByteArrayAsync
		$a_01_2 = {64 00 65 00 6c 00 6f 00 62 00 69 00 7a 00 6e 00 65 00 73 00 61 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 50 00 6f 00 63 00 70 00 7a 00 6b 00 6f 00 68 00 72 00 6a 00 6c 00 2e 00 64 00 6c 00 6c 00 } //00 00  delobiznesa.online/panel/uploads/Pocpzkohrjl.dll
	condition:
		any of ($a_*)
 
}