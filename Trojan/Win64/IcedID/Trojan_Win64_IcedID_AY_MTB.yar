
rule Trojan_Win64_IcedID_AY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 89 05 90 01 04 48 90 01 07 48 90 01 07 8b 89 90 01 04 8b 40 90 01 01 33 c1 35 90 01 04 48 90 01 06 8b 49 90 01 01 2b c8 8b c1 48 90 01 06 89 41 90 01 01 e9 90 01 04 b8 90 01 04 48 90 01 03 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AY_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 47 72 48 68 69 49 57 6a } //01 00  BGrHhiIWj
		$a_01_1 = {42 69 44 31 64 61 47 53 67 56 69 } //01 00  BiD1daGSgVi
		$a_01_2 = {47 45 47 66 42 4e 47 59 57 59 6d } //01 00  GEGfBNGYWYm
		$a_01_3 = {48 43 6a 33 6f 52 45 6e } //01 00  HCj3oREn
		$a_01_4 = {4a 30 51 45 49 56 30 56 4e 43 } //01 00  J0QEIV0VNC
		$a_01_5 = {42 49 64 54 74 58 61 55 79 4e 4b } //01 00  BIdTtXaUyNK
		$a_01_6 = {44 72 48 62 39 34 73 65 62 79 76 } //01 00  DrHb94sebyv
		$a_01_7 = {49 38 76 4d 55 52 72 50 4d 4c 69 } //01 00  I8vMURrPMLi
		$a_01_8 = {4b 37 71 6f 67 4e 4a 34 7a 42 59 } //01 00  K7qogNJ4zBY
		$a_01_9 = {4b 52 45 56 4d 59 67 62 66 54 43 } //00 00  KREVMYgbfTC
	condition:
		any of ($a_*)
 
}