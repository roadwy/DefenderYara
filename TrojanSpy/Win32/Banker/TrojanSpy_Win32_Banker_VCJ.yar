
rule TrojanSpy_Win32_Banker_VCJ{
	meta:
		description = "TrojanSpy:Win32/Banker.VCJ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 6e 00 63 00 6f 00 20 00 53 00 61 00 6e 00 74 00 61 00 6e 00 64 00 65 00 72 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 20 00 7c 00 20 00 42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 6a 00 75 00 6e 00 74 00 6f 00 73 00 20 00 2d 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 } //01 00  Banco Santander Brasil | Banco do juntos - Mozilla Firefox
		$a_01_1 = {53 00 65 00 6e 00 20 00 43 00 61 00 72 00 64 00 20 00 44 00 65 00 62 00 } //01 00  Sen Card Deb
		$a_01_2 = {40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  @gmail.com
		$a_01_3 = {5b 00 65 00 73 00 70 00 61 00 63 00 6f 00 5d 00 } //00 00  [espaco]
	condition:
		any of ($a_*)
 
}