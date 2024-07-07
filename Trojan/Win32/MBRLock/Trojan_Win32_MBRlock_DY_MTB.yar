
rule Trojan_Win32_MBRlock_DY_MTB{
	meta:
		description = "Trojan:Win32/MBRlock.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 50 6c 65 61 73 65 20 69 6e 70 75 74 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 21 } //1 Your disk have a lock!Please input the unlock password!
		$a_01_1 = {40 5c 5c 2e 5c 5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //1 @\\.\\physicaldrive0
		$a_01_2 = {55 8b ec 68 02 00 00 80 6a 00 68 01 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 11 00 01 06 68 12 00 01 52 68 03 00 00 00 bb } //1
		$a_03_3 = {8b 46 1c 68 e8 03 00 00 50 ff 15 90 01 03 00 c7 46 50 00 00 00 00 5e c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}