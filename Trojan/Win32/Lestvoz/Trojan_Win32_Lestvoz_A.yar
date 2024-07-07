
rule Trojan_Win32_Lestvoz_A{
	meta:
		description = "Trojan:Win32/Lestvoz.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 00 4d 00 61 00 69 00 6c 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5d 00 3d 00 } //1 [MailPassword]=
		$a_01_1 = {5b 00 44 00 65 00 74 00 65 00 63 00 74 00 49 00 50 00 5d 00 3d 00 } //1 [DetectIP]=
		$a_01_2 = {25 00 5b 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5d 00 } //1 %[Start Menu]
		$a_01_3 = {61 6c 69 67 6e 3d 22 63 65 6e 74 65 72 22 20 63 6c 61 73 73 3d 22 73 74 79 6c 65 35 22 3e } //1 align="center" class="style5">
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}