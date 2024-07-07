
rule Trojan_Win32_Qhost_DL{
	meta:
		description = "Trojan:Win32/Qhost.DL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 72 69 62 20 2b 68 20 2b 73 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 22 } //1 attrib +h +s "%windir%\system32\drivers\etc\hosts"
		$a_01_1 = {3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 af 73 74 73 } //1
		$a_01_2 = {65 63 68 6f 20 31 39 34 2e 38 2e 32 35 31 2e 31 34 37 } //1 echo 194.8.251.147
		$a_01_3 = {74 72 6f 79 5f 62 65 7a 5f 6d 61 69 6c 2e 62 61 74 } //1 troy_bez_mail.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}