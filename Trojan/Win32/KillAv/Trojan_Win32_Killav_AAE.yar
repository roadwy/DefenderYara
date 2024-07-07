
rule Trojan_Win32_Killav_AAE{
	meta:
		description = "Trojan:Win32/Killav.AAE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 4b 69 6c 6c 41 76 2e 64 6c 6c 00 45 78 65 63 4b 69 6c 6c 61 64 6f 72 00 } //10
		$a_01_1 = {51 56 5a 48 58 45 46 57 52 7a 49 77 4d 54 4a 63 59 58 5a 6e 64 57 6b 75 5a 58 68 6c } //1 QVZHXEFWRzIwMTJcYXZndWkuZXhl
		$a_01_2 = {51 56 5a 48 58 45 46 57 52 7a 49 77 4d 54 4e 63 59 58 5a 6e 64 32 52 7a 64 6d 4d 75 5a 58 68 6c } //1 QVZHXEFWRzIwMTNcYXZnd2RzdmMuZXhl
		$a_01_3 = {51 56 5a 48 58 45 46 57 52 7a 49 77 4d 54 49 3d } //1 QVZHXEFWRzIwMTI=
		$a_01_4 = {51 58 5a 68 63 33 52 56 53 53 35 6c 65 47 55 3d } //1 QXZhc3RVSS5leGU=
		$a_01_5 = {51 58 5a 68 63 33 52 54 64 6d 4d 75 5a 58 68 6c } //1 QXZhc3RTdmMuZXhl
		$a_01_6 = {51 56 5a 42 55 31 51 67 55 32 39 6d 64 48 64 68 63 6d 55 3d } //1 QVZBU1QgU29mdHdhcmU=
		$a_01_7 = {51 57 78 33 61 57 77 67 55 32 39 6d 64 48 64 68 63 6d 55 3d } //1 QWx3aWwgU29mdHdhcmU=
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}