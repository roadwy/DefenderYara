
rule Trojan_BAT_Zusy_PKM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 91 13 05 00 07 06 11 05 6e 21 34 0f cf 47 17 00 00 00 59 d2 6f ?? 00 00 0a 00 00 11 04 17 58 13 04 11 04 09 8e 69 } //3
		$a_00_1 = {75 00 73 00 61 00 61 00 61 00 61 00 } //2 usaaaa
		$a_00_2 = {24 62 39 62 63 65 64 34 34 2d 38 39 33 63 2d 34 64 65 66 2d 61 30 64 39 2d 33 35 30 64 34 36 33 31 61 63 66 35 } //1 $b9bced44-893c-4def-a0d9-350d4631acf5
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=6
 
}