
rule TrojanSpy_Win32_Bancos_ADA{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 Software\Borland\Delphi
		$a_01_1 = {53 61 6e 74 4e 77 73 } //1 SantNws
		$a_01_2 = {42 61 6e 63 6f 20 53 61 6e 74 61 6e 64 65 72 20 2f 20 52 65 61 6c } //1 Banco Santander / Real
		$a_01_3 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 @hotmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}