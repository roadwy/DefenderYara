
rule Trojan_Win32_Spynoon_RTA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_80_0 = {6c 74 6b 62 6a 71 74 68 77 79 6c } //ltkbjqthwyl  1
		$a_80_1 = {75 77 66 73 65 63 67 78 } //uwfsecgx  1
		$a_80_2 = {70 6f 65 67 63 6d 6b 62 61 77 } //poegcmkbaw  1
		$a_80_3 = {62 74 67 7a 6c 76 62 6a 73 73 } //btgzlvbjss  1
		$a_80_4 = {72 6f 69 63 6c 77 67 68 76 76 } //roiclwghvv  1
		$a_80_5 = {63 6a 71 6e 78 66 6f 67 66 74 } //cjqnxfogft  1
		$a_80_6 = {66 72 7a 65 72 78 76 67 77 } //frzerxvgw  1
		$a_80_7 = {6a 6f 66 69 71 6b 74 64 64 71 6b } //jofiqktddqk  1
		$a_80_8 = {6d 69 61 78 6e 6a 7a 7a 67 } //miaxnjzzg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=3
 
}
rule Trojan_Win32_Spynoon_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.RTA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 ee d4 00 00 ba 86 21 01 00 4b 2d e9 5b 00 00 f7 d2 81 c1 9d 35 00 00 } //1
		$a_01_1 = {81 eb a8 07 00 00 b8 5b 71 00 00 f7 d3 81 fb d2 47 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}