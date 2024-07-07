
rule Backdoor_BAT_AsyncRat_PA7_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRat.PA7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 7e 53 01 00 04 07 7e 53 01 00 04 07 91 20 9a 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e 53 01 00 04 8e 69 fe 04 0c 08 2d d7 } //2
		$a_80_1 = {68 74 74 70 3a 2f 2f 73 65 72 76 65 72 75 70 64 61 74 65 73 34 38 2e 67 61 2f 74 65 73 74 } //http://serverupdates48.ga/test  2
		$a_01_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_80_3 = {43 61 72 52 65 6e 74 61 6c 53 79 73 74 65 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 61 73 68 2e 70 64 62 } //CarRentalSystem\obj\Debug\Dash.pdb  1
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}