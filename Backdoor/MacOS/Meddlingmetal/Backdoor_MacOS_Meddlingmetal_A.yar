
rule Backdoor_MacOS_Meddlingmetal_A{
	meta:
		description = "Backdoor:MacOS/Meddlingmetal.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 ea 08 83 e2 3f 41 33 0c 92 89 c2 c1 ea 10 83 e2 3f c1 e8 18 83 e0 3f 41 33 0c 93 44 89 ca c1 c2 1c 33 94 37 8c 00 00 00 41 33 0c 86 89 d0 83 e0 3f 41 33 0c 87 89 d0 c1 e8 08 83 e0 3f 41 33 0c 84 89 d0 c1 e8 10 83 e0 3f 41 33 4c 85 00 c1 ea 18 } //01 00 
		$a_01_1 = {c1 ea 08 83 e2 3f 45 33 14 91 89 f2 c1 ea 10 83 e2 3f c1 ee 18 83 e6 3f 45 33 14 93 89 ca c1 c2 1c 42 33 94 00 84 00 00 00 45 33 14 b6 89 d6 83 e6 3f 45 33 14 b7 89 d6 c1 ee 08 83 e6 3f 45 33 14 b4 89 d6 c1 ee 10 83 e6 3f c1 ea 18 } //04 00 
		$a_01_2 = {4d 53 46 5f 4c 49 43 45 4e 53 45 } //00 00  MSF_LICENSE
	condition:
		any of ($a_*)
 
}