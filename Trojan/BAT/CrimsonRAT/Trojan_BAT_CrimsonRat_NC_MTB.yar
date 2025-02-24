
rule Trojan_BAT_CrimsonRat_NC_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 83 48 00 04 39 85 fe ff ff 26 20 01 00 00 00 } //2
		$a_01_1 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Debugger Detected
		$a_01_2 = {24 32 34 61 36 66 35 36 30 2d 61 33 34 36 2d 34 36 62 30 2d 61 61 66 62 2d 64 38 30 31 65 65 32 36 31 39 30 33 } //1 $24a6f560-a346-46b0-aafb-d801ee261903
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}