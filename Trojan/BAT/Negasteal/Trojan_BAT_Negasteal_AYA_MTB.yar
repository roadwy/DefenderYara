
rule Trojan_BAT_Negasteal_AYA_MTB{
	meta:
		description = "Trojan:BAT/Negasteal.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 18 6f 68 00 00 0a 13 19 11 19 09 d2 61 d2 13 19 11 19 09 d2 61 d2 13 19 00 00 11 18 17 58 13 18 11 18 19 06 6f 60 00 00 0a 28 69 00 00 0a fe 04 13 1a 11 1a 2d c7 } //7
		$a_01_1 = {24 43 35 45 39 41 33 46 37 2d 38 44 32 42 2d 34 41 36 45 2d 39 46 34 43 2d 37 42 31 41 35 45 38 44 33 46 36 43 } //2 $C5E9A3F7-8D2B-4A6E-9F4C-7B1A5E8D3F6C
		$a_01_2 = {50 61 72 73 65 42 69 74 6d 61 70 43 68 61 6e 6e 65 6c 73 } //1 ParseBitmapChannels
		$a_01_3 = {55 6e 77 72 61 70 43 6f 6c 6f 72 54 72 69 70 6c 65 74 } //1 UnwrapColorTriplet
		$a_01_4 = {73 63 72 65 65 6e 5f 73 61 76 65 72 5f 76 32 2e 46 6f 72 6d 32 2e 72 65 73 6f 75 72 63 65 73 } //1 screen_saver_v2.Form2.resources
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}