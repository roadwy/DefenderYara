
rule Trojan_Win64_LaplasClipper_B_MTB{
	meta:
		description = "Trojan:Win64/LaplasClipper.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 70 77 77 73 69 50 4d 59 6a 47 68 6e 68 67 43 6d 6a 71 76 2f 6d 7a 77 6a 37 34 61 68 74 37 65 4d 73 62 65 47 75 2d 7a 61 2f 36 38 45 34 34 56 4d 61 74 69 46 4d 37 43 4f 45 41 32 54 6e 2f 32 43 46 59 30 34 76 50 41 4e 73 61 7a 65 38 36 6c 73 6a 76 } //02 00  LpwwsiPMYjGhnhgCmjqv/mzwj74aht7eMsbeGu-za/68E44VMatiFM7COEA2Tn/2CFY04vPANsaze86lsjv
		$a_01_1 = {6e 65 74 2f 75 72 6c } //02 00  net/url
		$a_01_2 = {6f 73 2f 65 78 65 63 } //00 00  os/exec
	condition:
		any of ($a_*)
 
}