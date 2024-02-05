
rule Trojan_Win32_RedLine_MBIM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 12 d9 05 d0 68 41 00 d9 5d 84 d9 05 cc 68 41 00 d9 5d 84 d9 05 c8 68 41 00 d9 5d 84 d9 45 84 dc 1d d0 66 41 00 df e0 f6 c4 } //01 00 
		$a_01_1 = {72 6e 77 75 78 6f 6e 70 62 7a 71 6f 78 69 79 7a 6f 77 77 7a 63 6b 72 7a 78 65 79 6c 63 70 68 6b 6c 6d 70 64 61 73 64 6a 7a 72 67 62 73 78 64 71 68 6a 74 6d 72 79 72 71 72 70 61 67 6d 74 77 71 76 6a 67 75 6c 76 72 6d 74 64 61 79 } //01 00 
		$a_01_2 = {66 69 6f 76 70 66 62 76 79 6b 6c 67 67 68 64 68 65 6c 69 68 78 64 79 66 61 78 68 7a 66 6c 61 6d 69 70 6f 63 69 6a 6a 61 74 6f 68 78 6f 72 6e 69 63 79 6f 64 62 70 63 78 79 65 6a 6a 78 76 75 78 6f } //00 00 
	condition:
		any of ($a_*)
 
}