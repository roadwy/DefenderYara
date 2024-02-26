
rule Backdoor_BAT_DCRat_L_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 42 47 30 56 6e 49 6c 55 66 4f 43 49 53 42 4d 5a 4b 2e 57 54 54 39 35 76 50 6d 6d 45 4e 74 68 62 4e 6d 50 48 } //02 00  hBG0VnIlUfOCISBMZK.WTT95vPmmENthbNmPH
		$a_01_1 = {62 71 73 36 4a 4b 57 6c 41 44 71 6c 45 44 61 6c 4b 41 2e 4d 62 57 44 41 6b 47 46 66 6e 6d 41 45 53 43 35 50 4d } //02 00  bqs6JKWlADqlEDalKA.MbWDAkGFfnmAESC5PM
		$a_01_2 = {32 39 6b 50 63 6e 6b 51 4f 36 6b 45 53 4a 77 41 56 70 2e 46 34 78 4a 44 74 54 4e 39 59 42 34 65 72 72 33 44 43 } //02 00  29kPcnkQO6kESJwAVp.F4xJDtTN9YB4err3DC
		$a_01_3 = {44 00 61 00 72 00 6b 00 43 00 72 00 79 00 73 00 74 00 61 00 6c 00 20 00 52 00 41 00 54 00 } //00 00  DarkCrystal RAT
	condition:
		any of ($a_*)
 
}