
rule Spammer_Win32_Frotmael_A{
	meta:
		description = "Spammer:Win32/Frotmael.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 00 32 00 33 00 6c 00 65 00 6e 00 72 00 65 00 6b 00 7c 00 } //01 00  |23lenrek|
		$a_01_1 = {2f 00 61 00 6c 00 62 00 75 00 6d 00 2f 00 6d 00 61 00 69 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 75 00 3d 00 } //01 00  /album/mail.php?u=
		$a_01_2 = {53 71 55 65 45 7a 45 } //01 00  SqUeEzE
		$a_01_3 = {45 6d 61 69 6c 20 42 6f 6d 62 65 72 21 } //01 00  Email Bomber!
		$a_01_4 = {46 61 6b 65 20 45 6d 61 69 6c 3a } //00 00  Fake Email:
	condition:
		any of ($a_*)
 
}