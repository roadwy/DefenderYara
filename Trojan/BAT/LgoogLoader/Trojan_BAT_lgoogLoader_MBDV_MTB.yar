
rule Trojan_BAT_lgoogLoader_MBDV_MTB{
	meta:
		description = "Trojan:BAT/lgoogLoader.MBDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 00 42 00 64 00 57 00 73 00 35 00 77 00 37 00 51 00 5a 00 72 00 6f 00 57 00 32 00 42 00 36 00 35 00 78 00 62 00 7a 00 2b 00 67 00 44 00 38 00 53 00 74 00 4a 00 50 00 65 00 } //1 tBdWs5w7QZroW2B65xbz+gD8StJPe
		$a_01_1 = {2b 00 44 00 38 00 2f 00 34 00 2b 00 6b 00 30 00 4d 00 33 00 30 00 42 00 70 00 58 00 68 00 32 00 30 00 7a 00 63 00 36 00 79 00 62 00 49 00 6c 00 63 00 6a 00 35 00 62 00 61 00 67 00 2f 00 78 00 56 00 77 00 } //1 +D8/4+k0M30BpXh20zc6ybIlcj5bag/xVw
		$a_01_2 = {6a 00 37 00 4b 00 58 00 31 00 62 00 50 00 67 00 4a 00 4a 00 45 00 55 00 74 00 43 00 38 00 6b 00 7a 00 38 00 43 00 54 00 50 00 5a 00 70 00 78 00 2f 00 68 00 44 00 56 00 50 00 45 00 3d 00 } //1 j7KX1bPgJJEUtC8kz8CTPZpx/hDVPE=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}