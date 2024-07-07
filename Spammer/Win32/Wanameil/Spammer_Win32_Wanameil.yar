
rule Spammer_Win32_Wanameil{
	meta:
		description = "Spammer:Win32/Wanameil,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 48 3c 8b 4c 01 28 03 c8 74 11 6a 00 ff 75 08 50 ff d1 eb 07 33 c0 40 c3 } //10
		$a_01_1 = {50 49 50 45 4c 49 4e 49 4e 47 00 00 43 4f 4e 54 45 4e 54 00 4f 50 45 4e 20 5b } //10
		$a_01_2 = {2e 3f 41 56 78 6d 6d 6d 63 78 6d 6d 6a 63 64 67 40 40 00 } //10
		$a_01_3 = {52 43 50 54 20 54 4f 3a 3c 00 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 3c 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}