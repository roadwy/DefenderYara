
rule TrojanSpy_BAT_Remonct_A_bit{
	meta:
		description = "TrojanSpy:BAT/Remonct.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 00 49 00 35 00 2b 00 76 00 76 00 50 00 58 00 67 00 41 00 62 00 4e 00 6b 00 75 00 41 00 41 00 6f 00 76 00 63 00 6f 00 4e 00 72 00 78 00 61 00 39 00 53 00 6b 00 71 00 75 00 63 00 77 00 61 00 31 00 47 00 6d 00 6a 00 4a 00 78 00 47 00 6f 00 48 00 57 00 4c 00 2b 00 4e 00 62 00 48 00 41 00 44 00 52 00 62 00 50 00 59 00 32 00 72 00 30 00 59 00 31 00 6e 00 37 00 48 00 61 00 77 00 59 00 2b 00 6f 00 32 00 65 00 44 00 58 00 45 00 57 00 4d 00 6e 00 35 00 47 00 50 00 32 00 67 00 72 00 67 00 59 00 66 00 63 00 5a 00 67 00 3d 00 3d 00 } //2 oI5+vvPXgAbNkuAAovcoNrxa9Skqucwa1GmjJxGoHWL+NbHADRbPY2r0Y1n7HawY+o2eDXEWMn5GP2grgYfcZg==
		$a_01_1 = {71 00 50 00 46 00 38 00 31 00 70 00 4a 00 2f 00 66 00 53 00 63 00 2f 00 69 00 7a 00 6a 00 6d 00 6d 00 4e 00 39 00 64 00 35 00 67 00 3d 00 3d 00 } //2 qPF81pJ/fSc/izjmmN9d5g==
		$a_01_2 = {43 6c 69 33 6e 74 49 6e 73 74 34 6c 6c 65 72 } //1 Cli3ntInst4ller
		$a_01_3 = {53 54 34 52 54 55 50 4b 45 59 } //1 ST4RTUPKEY
		$a_01_4 = {45 4e 43 52 59 50 54 49 30 4e 4b 45 59 } //1 ENCRYPTI0NKEY
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}