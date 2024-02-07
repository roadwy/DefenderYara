
rule Worm_Win32_Wowstealer_A{
	meta:
		description = "Worm:Win32/Wowstealer.A,SIGNATURE_TYPE_PEHSTR,1a 00 18 00 1d 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 34 65 6e 6a 6f 79 } //01 00  game4enjoy
		$a_01_1 = {41 64 64 53 65 6c 66 4c 69 6e 6b 54 6f 48 74 6d 6c } //01 00  AddSelfLinkToHtml
		$a_01_2 = {68 74 6d 6c 5f 65 78 65 63 75 74 65 } //01 00  html_execute
		$a_01_3 = {69 66 72 61 6d 65 20 73 72 63 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e } //01 00  iframe src="http://www.
		$a_01_4 = {49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c } //01 00  Internet Account Manager\Accounts\
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 4c 6f 6f 6b 20 45 78 70 72 65 73 73 5c } //01 00  Microsoft\OutLook Express\
		$a_01_6 = {4d 41 50 49 53 65 6e 64 4d 61 69 6c } //01 00  MAPISendMail
		$a_01_7 = {4d 41 50 49 33 32 2e 44 4c 4c } //01 00  MAPI32.DLL
		$a_01_8 = {53 4d 54 50 3a 20 25 73 } //01 00  SMTP: %s
		$a_01_9 = {4d 41 49 4c 42 4f 44 59 } //01 00  MAILBODY
		$a_01_10 = {2f 44 61 74 61 2e 61 73 70 } //01 00  /Data.asp
		$a_01_11 = {26 74 65 78 74 3d } //01 00  &text=
		$a_01_12 = {64 61 74 61 74 79 70 65 3d 6d 61 69 6c 61 64 64 72 } //01 00  datatype=mailaddr
		$a_01_13 = {5b 25 73 3d 25 73 5d } //01 00  [%s=%s]
		$a_01_14 = {23 33 32 37 37 30 } //01 00  #32770
		$a_01_15 = {4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 } //01 00  Outlook Express
		$a_01_16 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_01_17 = {73 72 76 5f 25 64 5f 2e 6c 6f 67 } //01 00  srv_%d_.log
		$a_01_18 = {5a 49 50 45 58 45 } //01 00  ZIPEXE
		$a_01_19 = {5a 69 70 2e 45 78 65 } //01 00  Zip.Exe
		$a_01_20 = {70 61 74 63 68 2e 65 78 65 } //01 00  patch.exe
		$a_01_21 = {41 52 45 41 3d 25 73 } //01 00  AREA=%s
		$a_01_22 = {50 41 53 53 57 4f 52 44 3d 25 73 } //01 00  PASSWORD=%s
		$a_01_23 = {41 43 43 4f 55 4e 54 3d 25 73 } //01 00  ACCOUNT=%s
		$a_01_24 = {5b 57 4f 57 5d } //01 00  [WOW]
		$a_01_25 = {64 61 74 61 74 79 70 65 3d 77 6f 77 } //01 00  datatype=wow
		$a_01_26 = {47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 } //01 00  GxWindowClassD3d
		$a_01_27 = {57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //01 00  World of Warcraft
		$a_01_28 = {42 6c 69 7a 7a 61 72 64 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 2c 70 6c 73 20 6b 69 6e 64 6c 79 } //00 00  Blizzard Entertainment,pls kindly
	condition:
		any of ($a_*)
 
}