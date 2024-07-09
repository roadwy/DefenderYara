
rule PWS_Win32_Emotet_F{
	meta:
		description = "PWS:Win32/Emotet.F,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 69 6c 70 76 2e 65 78 65 } //10 \mailpv.exe
		$a_01_1 = {5c 6d 61 69 6c 70 76 2e 63 66 67 } //10 \mailpv.cfg
		$a_01_2 = {2f 73 78 6d 6c } //10 /sxml
		$a_01_3 = {2f 69 6e 2f 73 6d 74 70 2e 70 68 70 } //10 /in/smtp.php
		$a_03_4 = {6a 64 33 d2 59 f7 f1 83 f8 02 74 05 6a 02 58 eb 15 8b 35 ?? ?? ?? ?? 57 ff d6 ff 75 90 90 ff d6 ff 75 88 ff d6 33 c0 } //1
		$a_03_5 = {33 d2 6a 64 59 f7 f1 83 f8 02 74 05 6a 02 58 eb 11 56 8b 35 ?? ?? ?? ?? ff d6 53 ff d6 57 ff d6 33 c0 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=41
 
}