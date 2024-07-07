
rule Trojan_MacOS_BlackHole_A_MTB{
	meta:
		description = "Trojan:MacOS/BlackHole.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 6c 61 63 6b 48 6f 6c 65 20 52 41 54 20 2d 2d 3e } //1 BlackHole RAT -->
		$a_00_1 = {53 70 79 46 75 6e 63 74 69 6f 6e 73 52 65 63 6f 72 64 69 53 69 67 68 74 41 75 64 69 6f } //1 SpyFunctionsRecordiSightAudio
		$a_00_2 = {53 79 73 74 65 6d 41 75 74 6f 44 65 61 63 74 69 76 61 74 65 } //1 SystemAutoDeactivate
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}