
rule Trojan_BAT_AveMaria_NEE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 39 66 66 38 32 32 63 65 2d 38 37 38 33 2d 34 32 32 62 2d 38 66 34 61 2d 34 37 33 38 62 33 66 63 30 66 65 62 } //1 $9ff822ce-8783-422b-8f4a-4738b3fc0feb
		$a_01_1 = {67 65 74 66 4d 6f 6d 65 6e 74 6f 6d 64 32 78 } //1 getfMomentomd2x
		$a_01_2 = {6d 61 69 6e 42 65 61 6d 53 70 65 63 } //1 mainBeamSpec
		$a_01_3 = {54 68 65 20 46 6c 79 69 6e 67 20 42 65 61 72 20 6c 74 64 20 32 30 32 32 } //1 The Flying Bear ltd 2022
		$a_01_4 = {66 61 69 6c 75 72 65 57 61 79 } //1 failureWay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}