
rule TrojanDropper_Win32_Evotob_B{
	meta:
		description = "TrojanDropper:Win32/Evotob.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {3d 00 10 00 00 74 90 01 01 3d 00 20 00 00 72 90 01 01 3d 00 30 00 00 73 90 01 01 43 eb 90 01 01 3d 00 30 00 00 72 90 01 01 6a 02 eb 90 01 01 3d 00 40 00 00 72 90 01 01 6a 03 90 00 } //1
		$a_01_1 = {ff 65 40 40 ff 65 40 41 ff 65 40 42 ff 65 40 43 ff 65 40 46 ff 65 40 47 ff 65 40 } //1
		$a_00_2 = {c1 fa 1f 33 d1 69 d2 65 89 07 6c 83 c0 04 } //1
		$a_01_3 = {3e a3 03 00 00 00 3e c6 05 11 00 00 00 04 3e c7 05 5b 00 00 00 } //1
		$a_01_4 = {4d 61 7a 69 6c 6c 61 2f 35 2e 30 } //1 Mazilla/5.0
		$a_01_5 = {41 6e 74 69 6d 61 6c 77 61 72 65 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 72 6f 63 65 73 73 65 73 } //1 Antimalware\Exclusions\Processes
		$a_01_6 = {52 75 6e 59 6f 75 72 4d 61 6c 77 61 72 65 48 65 72 65 } //1 RunYourMalwareHere
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}