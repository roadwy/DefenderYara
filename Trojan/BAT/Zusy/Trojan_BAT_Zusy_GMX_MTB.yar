
rule Trojan_BAT_Zusy_GMX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 77 00 71 00 65 00 75 00 68 00 69 00 77 00 71 00 75 00 69 00 79 00 65 00 33 00 32 00 75 00 69 00 79 00 34 00 33 00 32 00 38 00 39 00 37 00 33 00 34 00 37 00 31 00 32 00 39 00 38 00 34 00 79 00 33 00 75 00 69 00 32 00 72 00 65 00 6b 00 6a 00 68 00 66 00 64 00 73 00 6b 00 6d 00 } //01 00  ewqeuhiwquiye32uiy43289734712984y3ui2rekjhfdskm
		$a_80_1 = {73 74 6f 72 6d 73 73 2e 78 79 7a 2f 61 70 69 } //stormss.xyz/api  00 00 
	condition:
		any of ($a_*)
 
}