
rule Backdoor_BAT_Bladabindi_ARAZ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 00 47 00 46 00 35 00 62 00 47 00 39 00 68 00 5a 00 43 00 35 00 6c 00 65 00 47 00 55 00 3d 00 } //2 UGF5bG9hZC5leGU=
		$a_01_1 = {62 00 6d 00 56 00 30 00 63 00 32 00 67 00 67 00 5a 00 6d 00 6c 00 79 00 5a 00 58 00 64 00 68 00 62 00 47 00 77 00 67 00 5a 00 47 00 56 00 73 00 5a 00 58 00 52 00 6c 00 49 00 47 00 46 00 73 00 62 00 47 00 39 00 33 00 5a 00 57 00 52 00 77 00 63 00 6d 00 39 00 6e 00 63 00 6d 00 46 00 74 00 49 00 43 00 49 00 3d 00 } //2 bmV0c2ggZmlyZXdhbGwgZGVsZXRlIGFsbG93ZWRwcm9ncmFtICI=
		$a_01_2 = {59 00 32 00 31 00 6b 00 4c 00 6d 00 56 00 34 00 5a 00 53 00 41 00 76 00 59 00 79 00 42 00 77 00 61 00 57 00 35 00 6e 00 49 00 44 00 41 00 67 00 4c 00 57 00 34 00 67 00 4d 00 69 00 41 00 6d 00 49 00 47 00 52 00 6c 00 62 00 43 00 41 00 69 00 } //2 Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCAi
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}