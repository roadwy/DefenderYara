
rule Trojan_BAT_CryptInject_NU_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 d5 a2 1f 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 63 00 00 00 82 00 00 00 a9 00 00 00 71 01 00 00 de } //01 00 
		$a_81_1 = {72 70 6b 66 64 73 64 64 66 73 64 6c 65 76 73 66 64 73 66 76 65 65 65 } //01 00  rpkfdsddfsdlevsfdsfveee
		$a_81_2 = {64 64 64 66 64 66 66 64 73 64 66 68 66 67 } //01 00  dddfdffdsdfhfg
		$a_81_3 = {67 73 65 66 68 66 73 73 64 6c 66 64 73 66 64 73 66 64 66 70 66 64 68 64 64 67 64 73 67 } //01 00  gsefhfssdlfdsfdsfdfpfdhddgdsg
		$a_81_4 = {53 68 6f 72 74 50 64 64 64 64 64 73 64 64 64 64 64 64 64 73 66 73 64 64 64 64 64 64 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //01 00  ShortPdddddsdddddddsfsdddddddddrocess Completed
		$a_81_5 = {53 68 6f 72 74 64 73 61 73 64 73 66 73 64 73 50 72 6f 63 64 65 73 73 20 53 74 61 72 74 65 64 } //01 00  ShortdsasdsfsdsProcdess Started
		$a_81_6 = {53 68 6f 72 74 50 64 64 73 61 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 66 73 66 6c 65 74 65 64 } //00 00  ShortPddsaddddddddddddddddddrocess Compfsfleted
	condition:
		any of ($a_*)
 
}