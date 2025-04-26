
rule Trojan_Win32_IcedId_ACD_MTB{
	meta:
		description = "Trojan:Win32/IcedId.ACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 72 6f 63 65 73 20 61 72 74 44 65 65 } //proces artDee  3
		$a_80_1 = {50 72 6f 20 73 68 69 } //Pro shi  3
		$a_80_2 = {50 40 6d 61 70 61 6e } //P@mapan  3
		$a_80_3 = {77 69 6e 5c 77 69 74 68 5c 77 6f 6d 65 6e } //win\with\women  3
		$a_80_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 } //C:\WINDOWS\SYSTEM32  3
		$a_80_5 = {46 69 6e 64 46 69 72 73 74 43 68 61 6e 67 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 41 } //FindFirstChangeNotificationA  3
		$a_80_6 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //GetWindowThreadProcessId  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}