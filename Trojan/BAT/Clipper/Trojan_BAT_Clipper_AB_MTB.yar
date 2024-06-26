
rule Trojan_BAT_Clipper_AB_MTB{
	meta:
		description = "Trojan:BAT/Clipper.AB!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 64 4c 69 6e 65 2e 43 6c 69 70 70 65 72 } //01 00  RedLine.Clipper
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 57 61 74 63 68 65 72 } //01 00  ClipboardWatcher
		$a_01_2 = {61 64 64 5f 4f 6e 43 6c 69 70 62 6f 61 72 64 43 68 61 6e 67 65 } //01 00  add_OnClipboardChange
		$a_01_3 = {43 68 61 6e 67 65 43 6c 69 70 62 6f 61 72 64 43 68 61 69 6e } //01 00  ChangeClipboardChain
		$a_01_4 = {62 00 28 00 62 00 63 00 31 00 7c 00 5b 00 31 00 33 00 5d 00 29 00 5b 00 61 00 2d 00 7a 00 41 00 2d 00 48 00 4a 00 2d 00 4e 00 50 00 2d 00 5a 00 30 00 2d 00 39 00 5d 00 7b 00 32 00 36 00 2c 00 33 00 35 00 7d 00 5c 00 62 00 } //00 00  b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}\b
	condition:
		any of ($a_*)
 
}