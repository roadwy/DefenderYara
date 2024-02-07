
rule Backdoor_AndroidOS_Basebridge_AB{
	meta:
		description = "Backdoor:AndroidOS/Basebridge.AB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {48 6f 69 70 72 4a 62 68 39 43 35 31 39 49 46 35 48 78 69 4c 39 49 30 68 38 63 4d 4e 75 65 7a 44 72 65 62 68 37 49 73 68 7a 32 4d 31 75 74 33 67 39 4e 72 32 30 43 33 35 7a 78 6c 70 7a 74 56 43 7a 77 75 57 30 74 33 77 7a 74 46 49 66 78 6b 52 66 63 42 62 75 74 4c 45 } //02 00  HoiprJbh9C519IF5HxiL9I0h8cMNuezDrebh7Ishz2M1ut3g9Nr20C35zxlpztVCzwuW0t3wztFIfxkRfcBbutLE
		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 62 61 74 74 65 72 79 2f 4b 69 6c 6c 54 68 72 65 65 53 69 78 5a 65 72 6f } //02 00  Lcom/android/battery/KillThreeSixZero
		$a_00_2 = {2f 73 66 2f 64 6e 61 2f 55 6e 7a 69 70 70 69 6e 67 } //00 00  /sf/dna/Unzipping
	condition:
		any of ($a_*)
 
}