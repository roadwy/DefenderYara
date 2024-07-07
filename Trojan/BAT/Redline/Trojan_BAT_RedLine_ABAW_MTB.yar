
rule Trojan_BAT_RedLine_ABAW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ABAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 1e 03 00 00 38 45 01 00 00 20 53 03 00 00 38 45 01 00 00 38 4a 01 00 00 26 16 3a 2e 01 00 00 20 85 00 00 00 38 43 01 00 00 20 85 00 00 00 38 43 01 00 00 38 48 01 00 00 38 4d 01 00 00 38 4e 01 00 00 16 39 4e 01 00 00 26 20 85 00 00 00 28 a4 00 00 06 06 02 28 8f 00 00 06 0a } //1
		$a_01_1 = {6b 70 49 41 41 6b 6d 68 64 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 kpIAAkmhdl.resources
		$a_01_2 = {6b 00 70 00 49 00 41 00 41 00 6b 00 6d 00 68 00 64 00 6c 00 } //1 kpIAAkmhdl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}