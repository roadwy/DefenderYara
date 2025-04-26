
rule Ransom_Win32_MauriCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/MauriCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_80_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 61 75 72 69 38 37 30 2f 72 61 6e 73 6f 6d 77 61 72 65 } //github.com/mauri870/ransomware  10
		$a_80_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 30 46 69 6c 65 73 } //main.encrypt0Files  5
		$a_80_2 = {53 65 6e 64 30 45 6e 63 72 79 70 74 65 64 30 50 61 79 6c 6f 61 64 } //Send0Encrypted0Payload  10
		$a_80_3 = {79 6f 75 72 20 64 65 76 69 63 65 20 68 61 76 65 20 62 65 65 6e 20 74 72 61 6e 73 66 65 72 72 65 64 20 74 6f 20 6f 75 72 20 73 65 72 76 65 72 20 66 6f 72 20 73 74 6f 72 61 67 65 } //your device have been transferred to our server for storage  5
		$a_80_4 = {44 65 73 6b 74 6f 70 2f 72 61 6e 73 6f 6d 77 61 72 65 2f 72 61 6e 73 6f 6d 77 61 72 65 2f 63 6d 64 2f 63 6f 6d 6d 6f 6e 2e 67 6f } //Desktop/ransomware/ransomware/cmd/common.go  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*10+(#a_80_3  & 1)*5+(#a_80_4  & 1)*10) >=35
 
}