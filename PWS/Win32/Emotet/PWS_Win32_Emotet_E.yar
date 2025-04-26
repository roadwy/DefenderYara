
rule PWS_Win32_Emotet_E{
	meta:
		description = "PWS:Win32/Emotet.E,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 69 6c 70 76 2e 65 78 65 } //1 \mailpv.exe
		$a_01_1 = {5c 6d 61 69 6c 70 76 2e 63 66 67 } //1 \mailpv.cfg
		$a_01_2 = {2f 73 78 6d 6c } //1 /sxml
		$a_01_3 = {2f 69 6e 2f 73 6d 74 70 2e 70 68 70 } //1 /in/smtp.php
		$a_03_4 = {6a 00 6a 1a 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? c3 } //1
		$a_03_5 = {6a 00 6a 1a 68 ?? ?? ?? ?? 6a 00 ff d7 } //1
		$a_03_6 = {b8 1f 85 eb 51 f7 64 24 ?? c1 ea 05 83 fa 02 74 07 b8 02 00 00 00 eb 11 56 8b 35 ?? ?? ?? ?? ff d6 57 ff d6 53 ff d6 33 c0 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*10) >=15
 
}