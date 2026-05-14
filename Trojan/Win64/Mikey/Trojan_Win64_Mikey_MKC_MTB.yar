
rule Trojan_Win64_Mikey_MKC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 64 69 74 43 61 72 64 73 2e 74 78 74 4a } //10 CreditCards.txtJ
		$a_01_1 = {42 6f 6f 6b 6d 61 72 6b 73 2e 74 78 74 44 6f 77 6e 6c 6f 61 64 73 2e 74 78 74 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //5 Bookmarks.txtDownloads.txtPasswords.txt
		$a_01_2 = {53 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 53 79 73 74 65 6d 49 6e 66 6f 2e 74 78 74 } //3 Screenshot.pngSystemInfo.txt
		$a_01_3 = {6e 61 63 63 65 73 73 4b 65 79 6e 61 6d 65 2e 64 6c 6c } //2 naccessKeyname.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=20
 
}