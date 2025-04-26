
rule Backdoor_Win32_Zegost_MB{
	meta:
		description = "Backdoor:Win32/Zegost.MB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {8a 19 32 da 40 3b c6 88 19 7c ec } //2
		$a_03_1 = {4d c6 44 24 ?? 6f c6 44 24 ?? 5a c6 44 24 ?? 68 } //2
		$a_00_2 = {2e 76 69 72 2c 6d 61 69 6e 00 } //1 瘮物洬楡n
		$a_00_3 = {25 73 5c 25 64 5f 6d 7a 2e 75 72 6c } //1 %s\%d_mz.url
		$a_00_4 = {47 6c 6f 62 61 6c 5c 7a 77 6a 20 25 64 } //1 Global\zwj %d
		$a_00_5 = {73 25 5c 73 65 63 69 76 72 65 73 5c 74 65 73 6c 6f 72 74 6e 6f 63 74 6e 65 72 72 75 63 5c 6d 65 74 73 79 73 } //1 s%\secivres\teslortnoctnerruc\metsys
		$a_01_6 = {6d 6f 7a 68 65 55 70 64 61 74 65 } //1 mozheUpdate
		$a_00_7 = {66 69 6c 65 3a 43 3a 5c 50 72 6f 67 72 61 7e 31 5c 25 25 50 72 6f 67 72 7e 31 5c 44 45 53 54 2e 42 41 54 00 } //1 楦敬䌺尺牐杯慲ㅾ╜倥潲牧ㅾ䑜卅⹔䅂T
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}