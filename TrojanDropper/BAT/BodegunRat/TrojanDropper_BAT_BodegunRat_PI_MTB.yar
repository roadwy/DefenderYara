
rule TrojanDropper_BAT_BodegunRat_PI_MTB{
	meta:
		description = "TrojanDropper:BAT/BodegunRat.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 5c 6f 62 6a 5c [0-10] 5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 2e 70 64 62 } //1
		$a_01_1 = {49 00 6d 00 41 00 46 00 75 00 63 00 6b 00 69 00 6e 00 67 00 46 00 75 00 64 00 56 00 69 00 72 00 75 00 73 00 2e 00 65 00 78 00 65 00 } //1 ImAFuckingFudVirus.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}