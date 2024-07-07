
rule Trojan_Win32_Sofacy_A_dha{
	meta:
		description = "Trojan:Win32/Sofacy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b c7 33 d2 f7 76 0c 8b 46 08 8a 04 02 32 44 39 ff 32 04 39 88 04 1f 4f } //10
		$a_03_1 = {52 65 67 53 66 c7 90 01 02 65 74 c6 45 be 56 88 55 bf 88 4d c0 c7 90 01 02 75 65 45 78 66 c7 90 01 02 57 00 90 00 } //10
		$a_03_2 = {65 6e 4b 65 c7 90 01 02 79 45 78 57 88 5d d5 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=20
 
}