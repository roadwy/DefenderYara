
rule Trojan_Win32_Qbot_DEK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {78 41 53 4a 4d 56 56 77 4a 4e } //01 00  xASJMVVwJN
		$a_81_1 = {53 65 59 45 79 47 4e 4f 53 4e } //01 00  SeYEyGNOSN
		$a_81_2 = {72 52 61 4a 4d 4a 74 4c 4d 63 } //01 00  rRaJMJtLMc
		$a_81_3 = {6f 79 4f 71 78 49 4e 6f 55 6f } //01 00  oyOqxINoUo
		$a_81_4 = {71 52 70 74 5a 42 79 6a 6a 56 } //01 00  qRptZByjjV
		$a_81_5 = {65 4d 54 73 73 61 70 6e 45 45 } //01 00  eMTssapnEE
		$a_81_6 = {4c 69 49 6d 4f 74 6f 68 6f 5a } //01 00  LiImOtohoZ
		$a_81_7 = {68 49 74 50 43 4c 63 6d 6a 5a } //01 00  hItPCLcmjZ
		$a_81_8 = {78 7a 44 56 65 54 68 66 49 75 } //01 00  xzDVeThfIu
		$a_81_9 = {71 76 4f 56 58 63 68 54 75 57 } //01 00  qvOVXchTuW
		$a_81_10 = {62 61 54 47 57 71 50 52 47 78 } //01 00  baTGWqPRGx
		$a_81_11 = {68 59 55 51 68 73 58 4b 5a 4f } //01 00  hYUQhsXKZO
		$a_81_12 = {42 6d 61 73 42 48 71 6e 48 47 } //01 00  BmasBHqnHG
		$a_81_13 = {73 59 6f 7a 71 65 57 4e 76 57 } //00 00  sYozqeWNvW
	condition:
		any of ($a_*)
 
}