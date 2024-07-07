
rule Trojan_Win32_ClipBanker_AV_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 56 69 54 52 51 62 39 34 41 39 38 64 69 78 72 6e 71 78 54 79 } //1 Go build ID: "ViTRQb94A98dixrnqxTy
		$a_01_1 = {6d 61 69 6e 2e 69 6d 70 6f 72 74 43 6c 69 70 62 6f 61 72 64 } //1 main.importClipboard
		$a_01_2 = {63 6c 69 70 62 6f 61 72 64 52 65 61 64 } //1 clipboardRead
		$a_01_3 = {63 6c 69 70 62 6f 61 72 64 57 72 69 74 65 } //1 clipboardWrite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}