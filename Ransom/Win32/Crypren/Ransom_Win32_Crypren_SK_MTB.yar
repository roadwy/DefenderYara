
rule Ransom_Win32_Crypren_SK_MTB{
	meta:
		description = "Ransom:Win32/Crypren.SK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 77 61 6c 6c 2e 68 74 6d } //01 00  Cryptowall.htm
		$a_01_1 = {66 75 6c 6c 73 63 72 65 65 6e 2e 76 62 73 } //01 00  fullscreen.vbs
		$a_01_2 = {46 49 4c 45 20 44 45 43 52 59 50 54 45 52 } //01 00  FILE DECRYPTER
		$a_01_3 = {53 65 6e 64 20 24 35 30 30 20 77 6f 72 74 68 20 6f 66 20 42 69 74 63 6f 69 6e } //00 00  Send $500 worth of Bitcoin
	condition:
		any of ($a_*)
 
}