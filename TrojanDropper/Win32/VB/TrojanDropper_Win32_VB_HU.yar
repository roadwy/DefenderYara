
rule TrojanDropper_Win32_VB_HU{
	meta:
		description = "TrojanDropper:Win32/VB.HU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 00 4f 00 30 00 4f 00 4f 00 4f 00 } //1 OO0OOO
		$a_01_1 = {4d 00 6a 00 6b 00 4c 00 66 00 6a 00 61 00 } //1 MjkLfja
		$a_01_2 = {65 00 2e 00 6d 00 73 00 73 00 73 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 6f 00 6e 00 67 00 6a 00 69 00 2f 00 } //1 e.msssm.com/tongji/
		$a_01_3 = {68 00 69 00 2e 00 62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 68 00 65 00 78 00 32 00 62 00 69 00 6e 00 2f 00 62 00 6c 00 6f 00 67 00 2f 00 69 00 74 00 65 00 6d 00 2f 00 63 00 61 00 34 00 38 00 31 00 30 00 33 00 63 00 61 00 63 00 65 00 62 00 63 00 66 00 32 00 64 00 39 00 36 00 64 00 64 00 64 00 38 00 37 00 33 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 hi.baidu.com/hex2bin/blog/item/ca48103cacebcf2d96ddd873.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}