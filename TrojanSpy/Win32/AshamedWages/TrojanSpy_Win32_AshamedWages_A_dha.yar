
rule TrojanSpy_Win32_AshamedWages_A_dha{
	meta:
		description = "TrojanSpy:Win32/AshamedWages.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_40_0 = {77 08 ff 75 08 e8 13 ff ff ff 89 07 83 c7 0c 83 3f ff 75 eb 01 } //1
		$a_ac_1 = {d0 aa c1 ca 08 e2 f7 61 c9 00 00 5d 04 00 00 70 b6 06 80 5c 2a 00 00 71 b6 06 80 00 00 01 00 08 00 14 00 54 72 6f 6a 61 6e 3a 56 42 41 2f 4f 62 66 75 73 21 4d 53 52 00 00 01 40 05 82 70 00 04 } //2816
	condition:
		((#a_40_0  & 1)*1+(#a_ac_1  & 1)*2816) >=2
 
}