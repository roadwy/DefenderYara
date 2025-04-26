
rule Trojan_BAT_Zusy_B_MTB{
	meta:
		description = "Trojan:BAT/Zusy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 75 08 00 00 1b 11 07 8f 91 00 00 01 25 71 91 00 00 01 11 07 04 58 0e 06 59 20 ff 00 00 00 5f d2 61 d2 81 91 00 00 01 } //2
		$a_01_1 = {38 32 34 32 37 36 31 63 2d 32 34 39 38 2d 34 36 65 36 2d 39 61 38 35 2d 66 33 66 36 61 39 62 39 65 33 66 32 } //1 8242761c-2498-46e6-9a85-f3f6a9b9e3f2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}