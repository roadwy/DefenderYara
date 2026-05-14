
rule Trojan_Win64_ReverseShell_VGY_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.VGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 53 65 6e 64 } //1 KeySend
		$a_01_1 = {31 39 32 2e 31 36 38 2e 38 35 2e 31 37 33 } //1 192.168.85.173
		$a_01_2 = {25 73 5c 73 63 72 2e 62 6d 70 } //1 %s\scr.bmp
		$a_01_3 = {53 63 72 53 65 6e 64 } //1 ScrSend
		$a_01_4 = {2f 73 63 72 65 65 6e 73 68 6f 74 } //1 /screenshot
		$a_01_5 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Google\Chrome\User Data\Default\Login Data
		$a_01_6 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Microsoft\Edge\User Data\Default\Login Data
		$a_01_7 = {43 72 65 64 53 65 6e 64 } //1 CredSend
		$a_01_8 = {62 72 6f 77 73 65 72 3d 25 73 26 75 72 6c 3d 25 73 26 75 73 65 72 6e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 } //1 browser=%s&url=%s&username=%s&password=%s
		$a_01_9 = {2f 63 72 65 64 73 } //1 /creds
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}