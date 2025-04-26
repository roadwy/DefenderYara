
rule Trojan_Win32_LummaStealer_NE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 0d a8 74 21 01 64 8b 09 8b 39 83 ff 00 74 ?? 8b 6f 18 3b 7d 30 } //3
		$a_03_1 = {74 1a 8b 75 00 39 f7 74 13 e8 ?? ?? ?? ?? 8b 0d a8 74 21 01 64 8b 09 89 31 8b 66 1c 83 ec } //2
		$a_01_2 = {6e 65 77 34 34 33 61 67 65 76 69 61 32 30 30 34 30 34 74 63 70 } //1 new443agevia200404tcp
		$a_01_3 = {47 00 65 00 6d 00 73 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 53 00 69 00 7a 00 65 00 } //1 Gems Folder Size
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}