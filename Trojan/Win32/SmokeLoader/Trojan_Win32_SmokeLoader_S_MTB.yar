
rule Trojan_Win32_SmokeLoader_S_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {42 65 7a 65 6d 61 74 65 76 61 6e 65 72 69 20 66 65 64 69 6c 6f 76 65 77 65 } //1 Bezematevaneri fedilovewe
		$a_01_1 = {66 65 64 61 62 6f 6d 61 6c 6f 7a 6f 73 61 74 65 62 75 73 75 68 75 7a 6f 67 69 73 61 72 6f 6a 6f 74 61 73 69 6b 75 79 69 6e 65 67 69 7a 6f 77 75 76 6f 76 65 7a 61 78 } //1 fedabomalozosatebusuhuzogisarojotasikuyinegizowuvovezax
		$a_01_2 = {74 61 63 75 73 75 68 69 63 61 67 65 } //1 tacusuhicage
		$a_01_3 = {78 75 70 61 6b 65 73 6f 70 6f 70 61 6b 75 78 6f } //1 xupakesopopakuxo
		$a_01_4 = {68 61 79 65 6c 69 79 61 70 61 76 69 7a 6f 76 6f 77 69 6e 69 67 61 78 6f 6d 61 63 6f 77 69 77 61 70 69 68 69 63 69 76 6f 6a 65 } //1 hayeliyapavizovowinigaxomacowiwapihicivoje
		$a_01_5 = {59 75 68 65 67 6f 76 65 73 6f 6e 20 64 61 78 65 6c 6f 77 61 6d 20 7a 69 74 61 6a 20 72 6f 62 6f 72 69 6c 65 } //1 Yuhegoveson daxelowam zitaj roborile
		$a_01_6 = {52 69 6d 61 76 6f 77 65 67 61 6c 20 62 75 68 61 76 69 6c 75 7a 75 20 74 65 73 6f 79 61 7a 20 6a 69 63 75 6b } //1 Rimavowegal buhaviluzu tesoyaz jicuk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}