
rule Trojan_Win64_ValleyRAT_ABVS_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.ABVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 49 8b c2 49 f7 f1 42 8a 04 02 41 30 04 0a 49 ff c2 4d 3b d3 72 } //5
		$a_80_1 = {43 72 65 61 74 65 53 74 65 61 6c 74 68 53 68 6f 72 74 63 75 74 } //CreateStealthShortcut  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_3 = {50 65 72 73 69 73 74 46 69 6c 65 } //PersistFile  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}