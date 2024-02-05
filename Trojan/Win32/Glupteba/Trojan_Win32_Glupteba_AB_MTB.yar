
rule Trojan_Win32_Glupteba_AB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {72 69 70 6f 70 65 6e 61 72 65 6e 65 6a 61 6d 65 6e 6f 6d 6f 74 6f } //ripopenarenejamenomoto  03 00 
		$a_80_1 = {6b 61 70 65 70 75 6a 61 73 61 70 69 76 61 7a 75 6a 69 6a 6f 77 6f 66 61 6b 6f } //kapepujasapivazujijowofako  03 00 
		$a_80_2 = {6d 6f 72 69 6e 75 72 65 6c 65 6e 69 76 61 79 6f 66 75 66 65 63 75 6d 69 63 61 78 75 66 6f } //morinurelenivayofufecumicaxufo  03 00 
		$a_80_3 = {6c 75 62 61 6e 61 78 75 78 69 63 61 63 75 62 65 72 65 74 61 7a 6f 66 65 78 69 64 69 68 69 6c } //lubanaxuxicacuberetazofexidihil  03 00 
		$a_80_4 = {6c 65 73 65 62 65 6a 61 77 65 73 61 6d 75 6c 75 } //lesebejawesamulu  03 00 
		$a_80_5 = {6d 75 73 69 7a 75 6e 69 63 61 74 65 77 69 77 6f 63 69 } //musizunicatewiwoci  03 00 
		$a_80_6 = {6a 75 6a 61 6c 6f 6a 6f 78 69 6a 75 } //jujalojoxiju  00 00 
	condition:
		any of ($a_*)
 
}