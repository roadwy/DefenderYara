
rule Trojan_Win64_IcedID_AZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 33 c9 e9 90 01 04 48 90 01 07 8b 84 24 90 01 04 66 90 01 02 74 90 01 01 8b 4c 24 90 01 01 33 c8 66 90 01 02 74 90 01 01 b9 90 01 04 e8 90 01 04 3a e4 74 90 01 01 48 90 01 04 48 90 01 07 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AZ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 62 70 6e 6e 6e 71 66 42 48 71 48 74 6d 71 77 70 78 49 5a 4e 45 79 5a 4f 5a 62 57 68 6a 79 } //01 00  AbpnnnqfBHqHtmqwpxIZNEyZOZbWhjy
		$a_01_1 = {42 46 62 56 74 43 79 6b 72 70 66 69 4f 73 71 55 57 6f 59 6e 4c 6f 64 7a 72 54 72 } //01 00  BFbVtCykrpfiOsqUWoYnLodzrTr
		$a_01_2 = {43 4f 4a 47 48 77 79 5a 74 46 6d 52 47 52 5a 52 63 44 74 6a 6d 66 } //01 00  COJGHwyZtFmRGRZRcDtjmf
		$a_01_3 = {46 46 41 68 6e 6a 69 65 68 41 55 43 55 71 6d 4c } //01 00  FFAhnjiehAUCUqmL
		$a_01_4 = {46 49 6d 4d 74 4f 6f 41 43 6a 55 44 65 70 45 65 42 51 75 52 } //01 00  FImMtOoACjUDepEeBQuR
		$a_01_5 = {47 77 6e 47 4b 75 44 72 6f 49 77 78 6d 6d 75 69 49 58 4a 63 42 4e } //00 00  GwnGKuDroIwxmmuiIXJcBN
	condition:
		any of ($a_*)
 
}