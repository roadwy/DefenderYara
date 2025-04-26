
rule PWS_Win32_Stimilina_A{
	meta:
		description = "PWS:Win32/Stimilina.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 66 69 67 2f 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //1 config/SteamAppData.vdf
		$a_01_1 = {2f 6d 61 72 6b 65 74 2f 65 6c 69 67 69 62 69 6c 69 74 79 63 68 65 63 6b 2f 3f 67 6f 74 6f 3d } //1 /market/eligibilitycheck/?goto=
		$a_01_2 = {2f 50 61 72 73 65 49 6e 76 3f 69 64 3d } //1 /ParseInv?id=
		$a_01_3 = {41 6c 65 78 5c 64 6f 63 75 6d 65 6e 74 73 5c } //1 Alex\documents\
		$a_01_4 = {2f 68 61 6c 66 5f 6c 69 66 65 5f 33 2f 69 6e 64 65 78 2e 70 68 70 } //1 /half_life_3/index.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}