
rule Backdoor_Win32_Delf_IM{
	meta:
		description = "Backdoor:Win32/Delf.IM,SIGNATURE_TYPE_PEHSTR,4a 00 49 00 0d 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {65 78 65 2e 74 73 6f 68 63 76 73 5c 73 72 65 76 69 72 64 5c } //0a 00  exe.tsohcvs\srevird\
		$a_01_2 = {6e 6f 67 6f 6c 6e 69 57 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 54 4e 20 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //0a 00  nogolniW\noisreVtnerruC\TN swodniW\tfosorciM\erawtfoS
		$a_01_3 = {74 73 69 4c 5c 73 6e 6f 69 74 61 63 69 6c 70 70 41 64 65 7a 69 72 6f 68 74 75 41 5c 65 6c 69 66 6f 72 50 64 72 61 64 6e 61 74 53 5c 79 63 69 6c 6f 50 6c 6c 61 77 65 72 69 46 5c 73 72 65 74 65 6d 61 72 61 50 5c 73 73 65 63 63 41 64 65 72 61 68 53 5c 73 65 63 69 76 72 65 53 5c 31 30 30 74 65 53 6c 6f 72 74 6e 6f 43 5c 6d 65 74 73 79 53 } //0a 00  tsiL\snoitacilppAdezirohtuA\eliforPdradnatS\yciloPllaweriF\sretemaraP\sseccAderahS\secivreS\100teSlortnoC\metsyS
		$a_01_4 = {6d 61 69 6c 40 6d 61 69 6c 2e 63 6f 6d } //0a 00  mail@mail.com
		$a_01_5 = {4e 49 43 4b 20 } //0a 00  NICK 
		$a_01_6 = {55 53 45 52 20 } //01 00  USER 
		$a_01_7 = {57 43 4b 42 53 56 30 31 } //01 00  WCKBSV01
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 50 61 6c 54 61 6c 6b } //01 00  Software\PalTalk
		$a_01_9 = {69 6e 69 2e 36 31 74 69 61 77 5c } //01 00  ini.61tiaw\
		$a_01_10 = {36 36 2e 31 30 32 2e 31 31 2e 39 39 } //01 00  66.102.11.99
		$a_01_11 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //01 00  @hotmail.com
		$a_01_12 = {37 36 36 36 3a 31 33 31 2e 39 39 31 2e 39 35 2e 32 31 32 } //00 00  7666:131.991.95.212
	condition:
		any of ($a_*)
 
}