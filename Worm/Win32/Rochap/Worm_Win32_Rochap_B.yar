
rule Worm_Win32_Rochap_B{
	meta:
		description = "Worm:Win32/Rochap.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 67 6c 65 5f 54 6f 6f 6c 5f 42 61 72 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 Google_Tool_Bar_Notification
		$a_01_1 = {52 65 73 6f 6c 76 69 6e 67 20 68 6f 73 74 6e 61 6d 65 20 25 73 2e } //1 Resolving hostname %s.
		$a_01_2 = {6d 61 72 61 6b 61 6d 69 7c 31 30 32 30 33 30 7c } //1 marakami|102030|
		$a_01_3 = {44 69 73 70 6f 73 69 74 69 6f 6e 2d 4e 6f 74 69 66 69 63 61 74 69 6f 6e 2d 54 6f } //1 Disposition-Notification-To
		$a_01_4 = {40 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 @terra.com.br
		$a_01_5 = {4c 69 6e 68 61 20 41 74 75 61 6c 20 53 4d 54 50 } //1 Linha Atual SMTP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}