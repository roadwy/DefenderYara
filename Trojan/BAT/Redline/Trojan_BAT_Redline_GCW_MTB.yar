
rule Trojan_BAT_Redline_GCW_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {32 64 65 6f 49 6b 45 33 63 49 75 } //2deoIkE3cIu  01 00 
		$a_80_1 = {36 54 48 59 4b 36 72 53 6e 32 34 52 } //6THYK6rSn24R  01 00 
		$a_80_2 = {71 57 4d 57 4d 70 35 6b 6b 36 4e } //qWMWMp5kk6N  01 00 
		$a_80_3 = {39 35 52 50 48 56 4a 61 4e 33 42 64 73 4f 41 51 59 59 6b 31 30 77 3d 3d } //95RPHVJaN3BdsOAQYYk10w==  01 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}