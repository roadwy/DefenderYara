
rule Trojan_WinNT_Vareids_A{
	meta:
		description = "Trojan:WinNT/Vareids.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {38 58 05 75 15 ff 77 10 ff 77 0c e8 ?? ?? ?? ?? c7 46 0c 34 00 00 c0 } //2
		$a_01_1 = {10 83 66 10 00 6a 04 c7 46 0c 22 00 00 c0 58 eb 03 } //2
		$a_01_2 = {8b 45 f0 8b 04 82 03 45 08 eb ee } //2
		$a_00_3 = {61 00 71 00 6d 00 67 00 75 00 } //3 aqmgu
		$a_00_4 = {6d 00 73 00 76 00 63 00 78 00 38 00 36 00 } //1 msvcx86
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*3+(#a_00_4  & 1)*1) >=5
 
}