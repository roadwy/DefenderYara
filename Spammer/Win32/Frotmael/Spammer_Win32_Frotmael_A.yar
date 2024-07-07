
rule Spammer_Win32_Frotmael_A{
	meta:
		description = "Spammer:Win32/Frotmael.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {7c 00 32 00 33 00 6c 00 65 00 6e 00 72 00 65 00 6b 00 7c 00 } //1 |23lenrek|
		$a_01_1 = {2f 00 61 00 6c 00 62 00 75 00 6d 00 2f 00 6d 00 61 00 69 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 75 00 3d 00 } //1 /album/mail.php?u=
		$a_01_2 = {53 71 55 65 45 7a 45 } //1 SqUeEzE
		$a_01_3 = {45 6d 61 69 6c 20 42 6f 6d 62 65 72 21 } //1 Email Bomber!
		$a_01_4 = {46 61 6b 65 20 45 6d 61 69 6c 3a } //1 Fake Email:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}