
rule TrojanSpy_Win32_AveMaria_STB{
	meta:
		description = "TrojanSpy:Win32/AveMaria.STB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 6c 6c 6f 63 6e 61 6b 2e 78 6d 6c } //ellocnak.xml  01 00 
		$a_80_1 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 } //Elevation:Administrator!new  01 00 
		$a_80_2 = {48 65 79 20 49 27 6d 20 41 64 6d 69 6e 00 } //Hey I'm Admin  00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}