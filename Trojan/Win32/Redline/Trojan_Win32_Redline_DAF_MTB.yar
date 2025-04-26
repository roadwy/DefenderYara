
rule Trojan_Win32_Redline_DAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f ?? 47 e2 } //1
		$a_01_1 = {47 78 6d 69 68 68 6b 71 6d 66 76 74 79 78 69 68 6b 75 6c 61 6a 76 71 79 75 74 72 78 63 74 62 69 62 64 6c 68 72 75 6f } //1 Gxmihhkqmfvtyxihkulajvqyutrxctbibdlhruo
		$a_01_2 = {66 72 74 74 66 62 6f 6b 71 70 6c 61 61 77 66 76 6c 78 76 65 6b 73 73 76 78 77 61 66 6f 7a 63 70 64 79 67 70 76 67 78 6c 66 73 72 71 6f 76 6d 66 6e 68 71 73 76 7a 77 66 75 62 6a 74 6f 74 } //1 frttfbokqplaawfvlxvekssvxwafozcpdygpvgxlfsrqovmfnhqsvzwfubjtot
		$a_01_3 = {6c 77 69 75 77 6b 69 73 6d 78 78 74 77 77 77 71 7a 77 6c 64 79 67 6a 6e 6e 79 78 68 6a 75 6e 79 63 74 74 63 62 75 64 76 61 73 66 74 65 7a 61 6a 69 69 72 73 6a 77 72 6d 71 6e 6f 67 64 75 78 78 6c 79 } //1 lwiuwkismxxtwwwqzwldygjnnyxhjunycttcbudvasftezajiirsjwrmqnogduxxly
		$a_01_4 = {66 76 6d 6c 75 69 7a 6b 6e 75 73 63 71 70 67 64 63 68 68 63 70 68 70 6f 6b 77 6d 6d 62 61 7a 70 6b 6c 6e 65 6a 76 } //1 fvmluizknuscqpgdchhcphpokwmmbazpklnejv
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}