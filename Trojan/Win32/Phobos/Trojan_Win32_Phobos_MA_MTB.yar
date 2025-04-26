
rule Trojan_Win32_Phobos_MA_MTB{
	meta:
		description = "Trojan:Win32/Phobos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {84 a4 55 c2 82 e6 a7 79 26 b2 a5 f7 43 03 f9 eb b5 41 21 8d 35 78 4b 25 81 a9 6e 1e 07 57 55 6b 48 d8 6b 99 20 8b f8 c8 75 d6 65 cd 19 62 20 d3 } //5
		$a_01_1 = {cb a6 7b c2 e7 e6 df 79 ee bf 9f f7 70 03 cb eb f7 dd a6 1a 5e 17 a4 15 ab 2c b9 8f c8 58 29 cf } //5
		$a_01_2 = {52 65 67 69 73 74 65 72 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 RegisterWaitForSingleObject
		$a_01_3 = {49 6e 69 74 43 6f 6d 6d 6f 6e 43 6f 6e 74 72 6f 6c 73 45 78 } //1 InitCommonControlsEx
		$a_01_4 = {50 6f 73 74 4d 65 73 73 61 67 65 57 } //1 PostMessageW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}