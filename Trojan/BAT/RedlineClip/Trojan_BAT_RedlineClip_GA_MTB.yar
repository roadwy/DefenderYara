
rule Trojan_BAT_RedlineClip_GA_MTB{
	meta:
		description = "Trojan:BAT/RedlineClip.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_80_0 = {52 65 64 4c 69 6e 65 2e 43 6c 69 70 70 65 72 } //RedLine.Clipper  1
		$a_80_1 = {44 6f 67 65 43 6f 69 6e } //DogeCoin  1
		$a_80_2 = {5a 43 61 73 68 } //ZCash  1
		$a_80_3 = {57 61 6c 6c 65 74 } //Wallet  1
		$a_80_4 = {43 6c 69 70 62 6f 61 72 64 57 61 74 63 68 65 72 } //ClipboardWatcher  1
		$a_80_5 = {57 4d 5f 44 52 41 57 43 4c 49 50 42 4f 41 52 44 } //WM_DRAWCLIPBOARD  1
		$a_80_6 = {4f 6e 43 6c 69 70 62 6f 61 72 64 43 68 61 6e 67 65 } //OnClipboardChange  1
		$a_80_7 = {72 65 67 65 78 } //regex  1
		$a_80_8 = {53 65 74 43 6c 69 70 62 6f 61 72 64 56 69 65 77 65 72 } //SetClipboardViewer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=8
 
}