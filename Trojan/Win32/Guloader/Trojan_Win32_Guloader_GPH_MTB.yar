
rule Trojan_Win32_Guloader_GPH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 61 73 73 61 6c 72 79 20 6c 69 64 65 6e 73 6b 61 62 73 6c 73 } //1 vassalry lidenskabsls
		$a_81_1 = {64 69 73 73 65 6b 65 72 69 6e 67 65 72 20 61 63 68 65 72 6f 6e 74 69 63 20 67 75 74 74 79 } //1 dissekeringer acherontic gutty
		$a_81_2 = {67 6c 79 70 74 69 63 69 61 6e 20 73 74 72 61 79 73 } //1 glyptician strays
		$a_81_3 = {75 6e 76 69 76 69 64 6e 65 73 73 20 72 65 6e 65 73 74 65 20 6e 73 73 65 6e 65 } //1 unvividness reneste nssene
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}