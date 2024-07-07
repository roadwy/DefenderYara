
rule Trojan_BAT_Remcos_SKJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 67 72 6f 75 6e 64 62 72 65 61 6b 69 6e 67 73 73 74 79 6c 65 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 6e 61 6e 6f 66 6f 6c 64 65 72 2f 69 6d 67 2d 66 69 6c 65 73 2f 56 46 4c 69 65 6e 74 2e 76 61 73 } //1 https://groundbreakingsstyle.com/wp-content/nanofolder/img-files/VFLient.vas
		$a_81_1 = {4f 78 79 50 6c 6f 74 74 69 6e 67 2e 45 57 47 69 62 72 61 6c 74 61 72 } //1 OxyPlotting.EWGibraltar
		$a_81_2 = {64 54 59 79 59 56 67 30 4e 6c 52 68 4e 33 41 33 5a 6d 68 68 64 45 6c 74 54 30 59 31 62 6d 56 78 4d 58 4a 69 59 57 56 50 56 32 4d 3d } //1 dTYyYVg0NlRhN3A3ZmhhdEltT0Y1bmVxMXJiYWVPV2M=
		$a_81_3 = {61 30 35 49 63 6b 73 35 65 6c 68 77 53 7a 55 79 64 45 39 56 56 77 3d 3d } //1 a05Icks5elhwSzUydE9VVw==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}