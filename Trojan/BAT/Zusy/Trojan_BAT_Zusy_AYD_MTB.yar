
rule Trojan_BAT_Zusy_AYD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 06 09 91 09 1f 2a 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69 32 d0 } //2
		$a_01_1 = {24 66 30 31 31 63 35 38 37 2d 61 37 36 37 2d 34 37 62 35 2d 62 30 32 32 2d 38 62 65 34 34 31 35 33 66 63 34 66 } //1 $f011c587-a767-47b5-b022-8be44153fc4f
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}