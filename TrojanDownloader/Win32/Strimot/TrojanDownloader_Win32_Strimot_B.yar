
rule TrojanDownloader_Win32_Strimot_B{
	meta:
		description = "TrojanDownloader:Win32/Strimot.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 00 74 00 65 00 6d 00 70 00 65 00 72 00 72 00 31 00 2e 00 74 00 6d 00 70 00 } //01 00  xtemperr1.tmp
		$a_01_1 = {64 00 72 00 69 00 6e 00 6b 00 73 00 74 00 65 00 65 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 33 00 2f 00 6a 00 6f 00 74 00 61 00 31 00 2e 00 74 00 6d 00 70 00 } //01 00  drinksteen.com/pictures3/jota1.tmp
		$a_01_2 = {44 00 65 00 43 00 72 00 59 00 70 00 74 00 65 00 44 00 00 00 } //01 00 
		$a_01_3 = {73 74 72 50 61 73 73 77 64 54 6f 52 65 63 6f 76 65 72 } //00 00  strPasswdToRecover
	condition:
		any of ($a_*)
 
}