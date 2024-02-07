
rule Trojan_BAT_CoinGrabber_MK_MTB{
	meta:
		description = "Trojan:BAT/CoinGrabber.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //01 00  WM_CLIPBOARDUPDATE
		$a_81_1 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //01 00  AddClipboardFormatListener
		$a_81_2 = {47 65 74 54 65 78 74 } //01 00  GetText
		$a_81_3 = {53 65 74 54 65 78 74 } //01 00  SetText
		$a_81_4 = {42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 } //00 00  Bitcoin-Grabber
	condition:
		any of ($a_*)
 
}