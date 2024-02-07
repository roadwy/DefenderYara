
rule Trojan_BAT_NjRat_NEDI_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {35 30 31 36 35 37 31 63 2d 33 36 33 39 2d 34 39 62 34 2d 62 32 64 35 2d 65 38 37 30 35 66 64 39 35 61 31 31 } //02 00  5016571c-3639-49b4-b2d5-e8705fd95a11
		$a_01_1 = {43 73 41 6e 74 69 50 72 6f 63 65 73 73 } //02 00  CsAntiProcess
		$a_01_2 = {73 74 72 65 61 6d 57 65 62 63 61 6d } //02 00  streamWebcam
		$a_01_3 = {47 65 74 41 6e 74 69 56 69 72 75 73 } //02 00  GetAntiVirus
		$a_01_4 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //02 00  get_MachineName
		$a_01_5 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 } //00 00  get_Clipboard
	condition:
		any of ($a_*)
 
}