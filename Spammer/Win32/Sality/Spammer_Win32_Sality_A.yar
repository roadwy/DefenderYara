
rule Spammer_Win32_Sality_A{
	meta:
		description = "Spammer:Win32/Sality.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 f9 24 0f 85 90 01 02 00 00 8b 55 08 03 90 01 02 ef ff ff 0f be 42 01 83 f8 72 0f 85 90 01 02 00 00 8b 4d 08 03 90 01 02 ef ff ff 0f be 51 02 83 fa 6e 0f 85 90 01 02 00 00 8b 45 08 90 00 } //02 00 
		$a_01_1 = {eb ab 8b 85 5c fb ff ff 35 11 f9 ad de 89 85 5c fb ff ff 8b 8d 5c fb ff ff 51 ff 15 } //02 00 
		$a_01_2 = {8a 12 32 14 08 8b 45 08 03 45 f0 88 10 e9 5f ff ff ff 8b 4d 10 8a 55 f4 88 91 00 01 00 00 8b 45 10 8a 4d ec 88 88 01 01 00 00 } //01 00 
		$a_01_3 = {5b 56 41 52 25 64 } //01 00  [VAR%d
		$a_01_4 = {53 50 4d 5f 49 44 3d 25 64 } //01 00  SPM_ID=%d
		$a_01_5 = {24 66 72 6f 6d 5f 6d 61 69 6c 24 } //01 00  $from_mail$
		$a_01_6 = {24 47 45 4e 5f 50 45 52 5f 4d 41 49 4c 24 3d } //01 00  $GEN_PER_MAIL$=
		$a_01_7 = {25 73 3f 66 75 63 6b 3d 70 6f 72 74 26 6d 78 5f 3d 25 64 26 73 6d 74 70 5f 3d 25 64 } //01 00  %s?fuck=port&mx_=%d&smtp_=%d
		$a_01_8 = {26 73 5f 69 64 3d 25 64 26 76 65 72 3d 25 64 26 72 3d 25 64 } //00 00  &s_id=%d&ver=%d&r=%d
	condition:
		any of ($a_*)
 
}