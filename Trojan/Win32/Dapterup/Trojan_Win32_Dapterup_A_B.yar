
rule Trojan_Win32_Dapterup_A_B{
	meta:
		description = "Trojan:Win32/Dapterup.A!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 64 65 6c 2e 62 61 74 00 } //2
		$a_01_1 = {31 08 3b 15 24 12 2b 05 37 03 37 } //1
		$a_00_2 = {5e 03 1e 67 9b 0c bb 56 66 6b 6d 64 4e c8 80 06 f1 fc } //1
		$a_01_3 = {8a 4c 30 ff 30 0c 30 83 e8 01 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}