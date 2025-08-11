
rule Trojan_Win32_GuLoader_RBD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {76 65 72 64 65 6e 73 6c 69 74 74 65 72 61 74 75 72 65 72 6e 65 } //1 verdenslitteraturerne
		$a_81_1 = {6d 69 72 7a 61 20 65 6e 75 6e 63 69 61 74 69 6f 6e } //1 mirza enunciation
		$a_81_2 = {62 79 72 65 74 73 64 6f 6d 6d 65 72 65 73 2e 65 78 65 } //1 byretsdommeres.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_GuLoader_RBD_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6b 69 72 6b 65 67 61 6e 67 65 5c 62 61 6c 74 68 65 75 73 5c 64 69 67 72 65 73 73 69 6f 6e } //1 kirkegange\baltheus\digression
		$a_81_1 = {50 72 65 63 6f 73 6d 69 63 61 6c 6c 79 5c 6d 75 6c 74 69 68 65 61 64 } //1 Precosmically\multihead
		$a_81_2 = {25 73 65 61 63 72 6f 73 73 25 5c 73 6f 6c 63 72 65 6d 65 } //1 %seacross%\solcreme
		$a_81_3 = {5c 6e 6f 6f 6b 79 5c 43 6f 6e 63 6f 6c 6f 75 72 2e 69 6e 69 } //1 \nooky\Concolour.ini
		$a_81_4 = {5c 73 70 65 72 6d 61 74 69 61 } //1 \spermatia
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}