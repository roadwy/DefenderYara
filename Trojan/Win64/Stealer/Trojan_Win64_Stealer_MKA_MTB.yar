
rule Trojan_Win64_Stealer_MKA_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_01_0 = {90 0f 57 c0 0f 11 45 2f 0f 57 c9 f3 0f 7f 4d 3f 48 8d 55 0f 48 83 7d 27 07 48 0f 47 55 0f 4c 8b 45 1f 48 8d 4d 2f } //25
		$a_01_1 = {5b 44 45 42 55 47 5d 20 44 65 63 72 79 70 74 65 64 20 4b 65 79 20 41 64 64 72 65 73 73 3a 20 30 78 25 70 } //5 [DEBUG] Decrypted Key Address: 0x%p
		$a_01_2 = {44 45 42 55 47 5d 20 46 61 69 6c 65 64 20 54 6f 20 46 65 74 63 68 20 4b 65 79 } //5 DEBUG] Failed To Fetch Key
		$a_01_3 = {5b 44 45 42 55 47 5d 20 55 6e 73 75 70 70 6f 72 74 65 64 20 62 72 6f 77 73 65 72 } //5 [DEBUG] Unsupported browser
		$a_81_4 = {63 68 72 6f 6d 65 2e 65 78 65 } //5 chrome.exe
		$a_81_5 = {77 68 61 6c 65 2e 65 78 65 } //5 whale.exe
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=50
 
}