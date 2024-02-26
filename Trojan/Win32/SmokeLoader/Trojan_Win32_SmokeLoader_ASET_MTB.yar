
rule Trojan_Win32_SmokeLoader_ASET_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 6f 00 64 00 6f 00 76 00 6f 00 68 00 6f 00 7a 00 61 00 64 00 6f 00 7a 00 75 00 6d 00 61 00 6a 00 65 00 6c 00 69 00 70 00 6f 00 } //01 00  jodovohozadozumajelipo
		$a_01_1 = {79 00 61 00 68 00 6f 00 68 00 65 00 76 00 65 00 72 00 65 00 74 00 65 00 6c 00 69 00 70 00 61 00 73 00 6f 00 62 00 69 00 73 00 61 00 64 00 61 00 64 00 61 00 } //01 00  yahoheveretelipasobisadada
		$a_01_2 = {67 00 69 00 64 00 75 00 76 00 61 00 6d 00 61 00 6b 00 65 00 76 00 65 00 64 00 6f 00 78 00 61 00 67 00 69 00 62 00 69 00 6b 00 65 00 79 00 69 00 62 00 69 00 78 00 } //01 00  giduvamakevedoxagibikeyibix
		$a_01_3 = {76 00 61 00 6d 00 6f 00 72 00 6f 00 67 00 75 00 6b 00 61 00 6a 00 61 00 63 00 } //05 00  vamorogukajac
		$a_01_4 = {6c 65 68 65 6c 61 72 6f 72 75 77 6f 6e 6f 7a 69 66 6f 76 6f 68 69 77 65 72 65 70 6f 6e 6f } //01 00  lehelaroruwonozifovohiwerepono
		$a_01_5 = {6c 00 61 00 72 00 6f 00 67 00 61 00 70 00 61 00 72 00 61 00 76 00 6f 00 73 00 6f 00 70 00 69 00 6d 00 6f 00 74 00 6f 00 68 00 69 00 7a 00 65 00 63 00 65 00 6e 00 61 00 66 00 69 00 66 00 75 00 } //01 00  larogaparavosopimotohizecenafifu
		$a_01_6 = {66 00 61 00 64 00 61 00 64 00 75 00 64 00 6f 00 68 00 61 00 77 00 61 00 66 00 6f 00 68 00 75 00 6b 00 61 00 62 00 65 00 6d 00 69 00 64 00 65 00 68 00 65 00 } //01 00  fadadudohawafohukabemidehe
		$a_01_7 = {74 00 61 00 74 00 69 00 6b 00 65 00 63 00 69 00 6a 00 75 00 6a 00 65 00 72 00 6f 00 62 00 6f 00 6b 00 6f 00 76 00 69 00 72 00 61 00 7a 00 } //01 00  tatikecijujerobokoviraz
		$a_01_8 = {78 00 69 00 6e 00 69 00 68 00 65 00 6b 00 65 00 6c 00 75 00 64 00 69 00 67 00 61 00 67 00 } //01 00  xinihekeludigag
		$a_01_9 = {6d 6f 72 65 62 75 63 6f 78 6f 7a 69 76 69 62 } //00 00  morebucoxozivib
	condition:
		any of ($a_*)
 
}