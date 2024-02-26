
rule Trojan_Win64_Cobaltstrike_DG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b fb 48 c1 f9 90 01 01 0f b6 c9 0f bf 14 48 c1 ea 90 01 01 83 e2 90 01 01 c1 ff 90 01 01 85 d2 74 90 00 } //01 00 
		$a_03_1 = {80 30 ee ff c1 48 8d 40 90 01 01 81 f9 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DG_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 89 cb 44 29 c3 41 89 d8 46 8d 0c 02 44 8b 05 90 01 04 8b 15 90 01 04 41 0f af d0 45 8d 04 11 8b 15 90 01 04 41 01 d0 8b 15 90 01 04 41 01 d0 8b 15 90 01 04 44 01 c2 48 63 d2 48 03 55 10 0f b6 12 31 ca 88 10 90 00 } //01 00 
		$a_81_1 = {51 41 6e 78 6b 3c 77 6e 67 77 7a 61 6a 76 6b 30 68 29 31 61 59 79 52 50 64 36 50 56 3f 75 39 2b 5f 38 69 67 64 57 50 26 47 45 6c 25 36 43 76 71 42 3c 72 70 73 4f 63 5a 5a 36 40 43 74 53 3c 6c 26 44 7a 48 46 78 55 46 29 6f 53 58 49 34 55 24 72 56 69 51 56 } //00 00  QAnxk<wngwzajvk0h)1aYyRPd6PV?u9+_8igdWP&GEl%6CvqB<rpsOcZZ6@CtS<l&DzHFxUF)oSXI4U$rViQV
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DG_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 54 03 90 01 01 48 89 f1 4c 8d 40 01 48 c1 f9 08 31 f2 31 ca 48 89 f1 48 c1 f9 10 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 90 01 01 49 39 f8 0f 8d 90 00 } //0a 00 
		$a_03_1 = {48 39 ce 7e 90 01 01 30 54 0b 90 01 01 48 8d 48 0a 48 39 ce 7e 90 01 01 30 54 0b 90 01 01 48 8d 48 0b 48 39 ce 7e 90 01 01 30 54 0b 90 01 01 48 8d 48 0c 48 39 ce 7e 90 01 01 30 54 0b 90 01 01 48 8d 48 0d 48 39 ce 7e 90 01 01 30 54 0b 90 01 01 48 83 c0 0e 48 39 c6 7e 90 00 } //0a 00 
		$a_03_2 = {30 54 0b 10 48 8d 48 90 01 01 48 39 ce 7e 90 01 01 30 54 0b 10 48 8d 48 90 01 01 48 39 ce 7e 90 01 01 30 54 0b 10 48 8d 48 90 01 01 48 39 ce 7e 90 01 01 30 54 0b 10 48 8d 48 90 01 01 48 39 ce 7e 90 01 01 48 83 c0 06 30 54 0b 10 48 39 c6 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}