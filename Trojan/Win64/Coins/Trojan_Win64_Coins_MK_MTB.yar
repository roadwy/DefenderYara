
rule Trojan_Win64_Coins_MK_MTB{
	meta:
		description = "Trojan:Win64/Coins.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4c 6f 67 67 65 72 20 45 72 72 6f 72 3a 20 4c 6f 67 73 20 64 69 72 65 63 74 6f 72 79 20 6e 6f 74 20 66 6f 75 6e 64 20 6f 72 20 65 6d 70 74 79 2e } //5 KeyLogger Error: Logs directory not found or empty.
		$a_01_1 = {52 65 63 65 69 76 65 64 20 63 6f 6d 6d 61 6e 64 3a 20 53 54 41 52 54 5f 52 45 56 45 52 53 45 5f 53 48 45 4c 4c } //5 Received command: START_REVERSE_SHELL
		$a_01_2 = {52 65 63 65 69 76 65 64 20 63 6f 6d 6d 61 6e 64 3a 20 53 54 4f 50 5f 52 45 56 45 52 53 45 5f 53 48 45 4c 4c } //5 Received command: STOP_REVERSE_SHELL
		$a_01_3 = {52 65 63 65 69 76 65 64 20 63 6f 6d 6d 61 6e 64 3a 20 53 45 4e 44 5f 52 45 56 45 52 53 45 5f 53 48 45 4c 4c } //5 Received command: SEND_REVERSE_SHELL
		$a_01_4 = {45 78 70 69 72 63 79 3a } //5 Expircy:
		$a_01_5 = {43 6f 6f 6b 69 65 73 20 42 72 6f 77 73 65 72 3a } //5 Cookies Browser:
		$a_01_6 = {70 61 73 73 77 6f 72 64 20 63 6f 6c 6c 65 63 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e 20 55 70 6c 6f 61 64 69 6e 67 20 5a 49 50 20 66 69 6c 65 3a } //5 password collection complete. Uploading ZIP file:
		$a_01_7 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //2 BraveSoftware\Brave-Browser\User Data
		$a_01_8 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //2 Microsoft\Edge\User Data
		$a_01_9 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 Google\Chrome\User Data
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1) >=40
 
}