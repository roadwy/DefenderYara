
rule Trojan_Win32_Fsysna_GND_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 2e 63 6f 6d 2f 76 69 72 75 73 2e 65 78 65 } //1 server.com/virus.exe
		$a_80_1 = {74 6d 70 6a 68 67 54 46 7a 74 66 5a 37 38 39 74 66 7a 54 44 74 } //tmpjhgTFztfZ789tfzTDt  1
		$a_01_2 = {76 69 72 75 73 2e 65 78 65 49 47 44 41 49 45 6a 68 4d 57 4e 4a 58 42 } //1 virus.exeIGDAIEjhMWNJXB
		$a_80_3 = {61 6e 6e 6f 66 61 69 65 } //annofaie  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}