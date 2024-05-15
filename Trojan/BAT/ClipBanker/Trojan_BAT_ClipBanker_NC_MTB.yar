
rule Trojan_BAT_ClipBanker_NC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {59 17 63 5f 91 04 60 61 d1 9d 06 } //01 00 
		$a_81_1 = {43 6c 69 70 62 6f 61 72 64 } //01 00  Clipboard
		$a_81_2 = {41 73 79 6e 63 43 6c 69 70 62 6f 61 72 64 4d 61 6e 61 67 65 72 } //00 00  AsyncClipboardManager
	condition:
		any of ($a_*)
 
}