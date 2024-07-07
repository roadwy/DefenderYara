
rule Trojan_BAT_ClipBanker_GC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 70 65 72 } //Clipper  10
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_2 = {52 65 67 65 78 } //Regex  1
		$a_80_3 = {63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 } //choice /C Y /N /D Y /T  1
		$a_80_4 = {73 63 68 74 61 73 6b 73 } //schtasks  1
		$a_80_5 = {30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d } //0x[a-fA-F0-9]{40}  1
		$a_80_6 = {41 50 50 44 41 54 41 } //APPDATA  1
		$a_80_7 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //processhacker  1
		$a_80_8 = {70 72 6f 63 65 78 70 } //procexp  1
		$a_80_9 = {74 61 73 6b 6d 67 72 } //taskmgr  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=16
 
}
rule Trojan_BAT_ClipBanker_GC_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0c 00 00 "
		
	strings :
		$a_80_0 = {73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d 2f 74 72 61 64 65 6f 66 66 65 72 } //steamcommunity.com/tradeoffer  10
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_2 = {57 4d 5f 44 52 41 57 43 4c 49 50 42 4f 41 52 44 } //WM_DRAWCLIPBOARD  1
		$a_80_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 56 69 65 77 65 72 } //SetClipboardViewer  1
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_5 = {41 70 61 72 74 6d 65 6e 74 53 74 61 74 65 } //ApartmentState  1
		$a_80_6 = {76 6d 77 61 72 65 74 72 61 79 } //vmwaretray  1
		$a_80_7 = {76 62 6f 78 73 65 72 76 69 63 65 } //vboxservice  1
		$a_80_8 = {76 6d 74 6f 6f 6c 73 64 } //vmtoolsd  1
		$a_80_9 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  1
		$a_80_10 = {58 47 49 6f 63 58 78 77 4b 56 74 68 4c 58 6f 77 4c 54 6c 64 65 7a 51 78 66 56 78 69 } //XGIocXxwKVthLXowLTldezQxfVxi  1
		$a_80_11 = {58 47 49 77 65 46 74 68 4c 57 5a 42 4c 55 59 77 4c 54 6c 64 65 7a 51 77 66 56 78 69 } //XGIweFthLWZBLUYwLTldezQwfVxi  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=19
 
}