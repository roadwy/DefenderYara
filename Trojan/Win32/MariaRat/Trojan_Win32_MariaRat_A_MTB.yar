
rule Trojan_Win32_MariaRat_A_MTB{
	meta:
		description = "Trojan:Win32/MariaRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a 7b } //1 Elevation:Administrator!new:{
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_01_2 = {53 4d 54 50 20 50 61 73 73 77 6f 72 64 } //1 SMTP Password
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 } //1 cmd.exe /C ping 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}