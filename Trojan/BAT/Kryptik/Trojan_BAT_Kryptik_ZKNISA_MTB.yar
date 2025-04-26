
rule Trojan_BAT_Kryptik_ZKNISA_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ZKNISA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 61 37 61 38 35 32 37 63 2d 33 37 61 65 2d 34 34 33 62 2d 38 64 61 61 2d 36 31 30 30 31 63 62 64 32 36 35 38 } //10 $a7a8527c-37ae-443b-8daa-61001cbd2658
		$a_01_1 = {41 64 64 43 42 53 5f 56 61 6c 75 65 73 } //1 AddCBS_Values
		$a_01_2 = {46 4c 75 78 43 65 6e 74 65 72 } //1 FLuxCenter
		$a_01_3 = {50 6c 61 79 53 6f 75 6e 64 } //1 PlaySound
		$a_01_4 = {4f 62 6a 65 63 74 49 64 65 6e 74 69 66 69 65 72 } //1 ObjectIdentifier
		$a_01_5 = {50 6c 61 79 41 53 6f 75 6e 64 } //1 PlayASound
		$a_01_6 = {43 68 65 63 6b 46 6f 72 43 6f 6c 6c 69 73 69 6f 6e } //1 CheckForCollision
		$a_01_7 = {63 68 65 63 6b 57 69 6e 6e 65 72 } //1 checkWinner
		$a_01_8 = {48 69 74 73 50 61 64 64 6c 65 } //1 HitsPaddle
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}