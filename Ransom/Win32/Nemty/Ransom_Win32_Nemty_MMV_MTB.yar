
rule Ransom_Win32_Nemty_MMV_MTB{
	meta:
		description = "Ransom:Win32/Nemty.MMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 3a 58 66 89 45 ee 6a 5c 58 66 89 45 90 01 01 33 c0 66 89 45 90 01 01 8d 45 ec 83 c1 90 01 01 50 66 89 4d 90 01 01 ff 15 90 01 04 6a 04 57 89 45 90 00 } //01 00 
		$a_80_1 = {36 4e 45 50 48 49 4c 49 4d 2d 44 45 43 52 59 50 54 2e 74 78 74 } //6NEPHILIM-DECRYPT.txt  00 00 
	condition:
		any of ($a_*)
 
}