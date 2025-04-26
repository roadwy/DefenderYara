
rule Worm_BAT_Nepinseft_B{
	meta:
		description = "Worm:BAT/Nepinseft.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 45 46 54 55 31 64 50 55 6b 51 36 49 41 3d 3d } //1 UEFTU1dPUkQ6IA==
		$a_01_1 = {54 6d 56 33 49 46 42 44 49 45 6c 75 5a 6d 56 6a 64 47 56 6b 49 41 3d 3d } //1 TmV3IFBDIEluZmVjdGVkIA==
		$a_01_2 = {61 48 52 30 63 44 6f 76 4c 33 64 6f 59 58 52 70 63 32 31 35 61 58 41 75 59 32 39 74 4c 32 46 31 64 47 39 74 59 58 52 70 62 32 34 76 62 6a 41 35 4d 6a 4d 77 4f 54 51 31 4c 6d 46 7a 63 41 3d } //1 aHR0cDovL3doYXRpc215aXAuY29tL2F1dG9tYXRpb24vbjA5MjMwOTQ1LmFzcA=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}