
rule PWS_Win32_Tibia_BU{
	meta:
		description = "PWS:Win32/Tibia.BU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 70 6c 61 63 65 5f 69 6e 66 32 2e 70 68 70 } //1 GET /place_inf2.php
		$a_00_1 = {5a 6e 61 6c 65 7a 69 6f 6e 6f 20 74 69 62 69 65 20 50 49 44 20 2d 20 25 64 } //1 Znaleziono tibie PID - %d
		$a_03_2 = {26 70 61 63 63 3d [0-10] 26 63 68 61 72 3d [0-10] 26 6e 6f 74 65 3d } //1
		$a_00_3 = {5c 69 6e 66 6f 72 6d 61 74 79 6b 61 5c 72 6f 6f 74 6b 69 74 } //1 \informatyka\rootkit
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}