
rule Trojan_Win32_Emotet_GH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 0a 03 c1 b9 c1 3a 00 00 99 f7 f9 8b 4d 90 01 01 2b 55 90 01 01 03 55 90 01 01 8a 04 32 8b 55 90 01 01 30 04 0a 41 3b 4d 90 01 01 89 4d 90 01 01 b9 c1 3a 00 00 72 90 00 } //10
		$a_80_1 = {59 77 61 57 29 43 65 2a 45 66 4f 53 6c 4e 74 49 63 33 5f 5f 77 4f 4a 59 5a 25 56 24 4d 7a 54 25 75 58 58 52 55 32 6f 36 5f 41 3c 41 71 75 46 35 44 74 3c 39 52 72 38 5f 30 6d } //YwaW)Ce*EfOSlNtIc3__wOJYZ%V$MzT%uXXRU2o6_A<AquF5Dt<9Rr8_0m  10
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10) >=10
 
}