
rule Trojan_BAT_RedLineStealer_RPP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {34 00 39 00 2e 00 31 00 32 00 2e 00 32 00 31 00 37 00 2e 00 31 00 30 00 36 00 } //1 49.12.217.106
		$a_01_1 = {66 00 6c 00 65 00 78 00 2e 00 7a 00 69 00 70 00 } //1 flex.zip
		$a_01_2 = {4c 00 69 00 6e 00 6b 00 43 00 72 00 69 00 61 00 74 00 65 00 } //1 LinkCriate
		$a_01_3 = {4d 00 61 00 64 00 61 00 72 00 61 00 } //1 Madara
		$a_01_4 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 SpecialFolder
		$a_01_5 = {46 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 FtpWebResponse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}