
rule Trojan_BAT_Zusy_HND_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 46 45 51 52 42 32 36 58 33 50 44 45 44 46 57 56 42 4e 4e 7a 37 5a 35 4c 71 76 4a 61 59 68 42 71 7a 4d 50 49 51 62 39 33 59 70 6c 67 4e 48 50 4d 34 31 38 39 6c 49 5a 63 56 52 55 4b 49 6b 76 70 44 78 36 58 79 54 79 49 6d 42 65 32 4a 57 71 47 6d 50 4a 59 4f 47 5a 72 75 4b 64 34 63 50 48 77 44 43 6e 67 33 77 [0-ff] 54 65 6d 70 6c 61 74 65 [0-30] 41 6c 6c 6f 77 4d 75 6c 74 69 70 6c 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}