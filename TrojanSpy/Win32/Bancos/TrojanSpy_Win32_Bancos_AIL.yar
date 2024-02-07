
rule TrojanSpy_Win32_Bancos_AIL{
	meta:
		description = "TrojanSpy:Win32/Bancos.AIL,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 50 6c 41 70 70 6c 65 74 } //02 00  CPlApplet
		$a_01_1 = {49 6d 61 67 65 39 43 6c 69 63 6b } //03 00  Image9Click
		$a_01_2 = {69 6d 67 54 61 6d 70 61 43 6c 69 63 6b } //03 00  imgTampaClick
		$a_01_3 = {70 6e 6c 53 65 67 49 45 72 72 6f } //04 00  pnlSegIErro
		$a_01_4 = {74 6d 72 42 6c 6f 71 54 69 6d 65 72 } //00 00  tmrBloqTimer
		$a_00_5 = {5d 04 00 00 20 b3 02 80 } //5c 25 
	condition:
		any of ($a_*)
 
}