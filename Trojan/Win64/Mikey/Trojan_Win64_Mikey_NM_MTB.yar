
rule Trojan_Win64_Mikey_NM_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 89 84 24 a0 00 00 00 48 8b d9 48 89 4c 24 20 48 8d 05 16 a9 10 00 48 89 44 24 40 48 c7 44 24 48 12 00 00 00 45 33 c0 48 8d 54 24 40 48 8d 4c 24 60 e8 66 ea fe ff 90 48 8d 8c 24 80 00 00 00 e8 08 87 00 00 90 4c 8d 44 24 60 48 8b d0 } //2
		$a_01_1 = {48 8d 8c 24 80 00 00 00 e8 b9 53 00 00 90 48 8d 4c 24 60 e8 ae 53 00 00 48 8b c3 eb 05 } //1
		$a_01_2 = {5f 64 65 63 72 79 70 74 5f 70 61 79 6d 65 6e 74 73 2e 74 78 74 } //1 _decrypt_payments.txt
		$a_01_3 = {4b 69 6c 6c 42 72 6f 77 73 65 72 50 72 6f 63 65 73 73 65 73 } //1 KillBrowserProcesses
		$a_01_4 = {5f 64 65 63 72 79 70 74 5f 63 6f 6f 6b 69 65 73 2e 74 78 74 } //1 _decrypt_cookies.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}