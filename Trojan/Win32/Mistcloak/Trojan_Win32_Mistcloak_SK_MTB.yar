
rule Trojan_Win32_Mistcloak_SK_MTB{
	meta:
		description = "Trojan:Win32/Mistcloak.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 75 73 62 2e 69 6e 69 } //1 \usb.ini
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 5c 50 72 6f 74 65 63 74 69 6f 6e 20 66 6f 72 20 41 75 74 6f 72 75 6e 5c 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 75 73 62 2e 69 6e 69 } //1 autorun.inf\Protection for Autorun\System Volume Information\usb.ini
		$a_01_2 = {47 3a 5c 70 72 6f 6a 65 63 74 5c 41 50 54 5c 55 } //1 G:\project\APT\U
		$a_01_3 = {5c 6e 65 77 5c 75 32 65 63 5c 52 65 6c 65 61 73 65 5c 75 32 65 63 2e 70 64 62 } //1 \new\u2ec\Release\u2ec.pdb
		$a_01_4 = {53 65 72 76 65 72 47 65 74 55 73 62 44 65 76 4e 61 6d 65 } //1 ServerGetUsbDevName
		$a_01_5 = {53 65 72 76 65 72 47 65 74 55 73 62 44 65 76 53 74 61 74 75 73 } //1 ServerGetUsbDevStatus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}