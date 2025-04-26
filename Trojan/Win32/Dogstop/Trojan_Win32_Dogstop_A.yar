
rule Trojan_Win32_Dogstop_A{
	meta:
		description = "Trojan:Win32/Dogstop.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 70 00 79 00 72 00 6f 00 5a 00 4f 00 4e 00 45 00 5c 00 4b 00 4b 00 39 00 } //1 spyroZONE\KK9
		$a_01_1 = {53 00 50 00 59 00 52 00 4f 00 20 00 4b 00 69 00 44 00 20 00 77 00 69 00 6c 00 6c 00 20 00 73 00 65 00 6e 00 64 00 20 00 61 00 6e 00 6f 00 74 00 68 00 65 00 72 00 20 00 6c 00 69 00 6f 00 6e 00 20 00 66 00 6f 00 72 00 20 00 79 00 6f 00 75 00 } //1 SPYRO KiD will send another lion for you
		$a_01_2 = {42 00 79 00 70 00 61 00 73 00 73 00 20 00 4b 00 39 00 20 00 57 00 65 00 62 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 Bypass K9 Web Protection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}