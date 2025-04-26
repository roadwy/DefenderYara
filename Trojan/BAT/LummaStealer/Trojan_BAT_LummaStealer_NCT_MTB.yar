
rule Trojan_BAT_LummaStealer_NCT_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 75 4f 66 58 52 55 6e 48 54 4f 68 76 6a 4e 76 6e 6c 78 72 } //2 PuOfXRUnHTOhvjNvnlxr
		$a_01_1 = {4c 73 58 49 42 4b 6e 57 71 6d 6e 7a 4d 61 42 6a 74 70 79 54 69 6f 76 4d 4c 69 55 5a } //1 LsXIBKnWqmnzMaBjtpyTiovMLiUZ
		$a_01_2 = {74 73 72 6e 4b 4d 4d 52 57 61 53 6d 67 49 47 42 61 64 54 6d 52 44 56 4b 2e 64 6c 6c } //1 tsrnKMMRWaSmgIGBadTmRDVK.dll
		$a_01_3 = {49 76 52 7a 66 66 74 56 41 65 78 6b 48 6f 51 4a 50 72 63 77 4e 4b 7a 63 68 6f 79 5a 51 } //1 IvRzfftVAexkHoQJPrcwNKzchoyZQ
		$a_01_4 = {45 4d 67 56 6b 58 52 42 6c 56 69 48 78 69 4b 4a 6f 47 58 6f 6d 44 6e 6b 6f 7a 6b 72 2e 64 6c 6c } //1 EMgVkXRBlViHxiKJoGXomDnkozkr.dll
		$a_01_5 = {63 68 4f 6c 6d 48 79 7a 4d 66 4e 56 77 68 68 6e 4f 66 69 7a 4d 4c 71 69 7a } //1 chOlmHyzMfNVwhhnOfizMLqiz
		$a_01_6 = {6e 78 74 53 76 58 56 67 4a 58 65 6c 79 47 4c 42 66 75 64 64 77 6e 69 68 69 53 4c 62 2e 64 6c 6c } //1 nxtSvXVgJXelyGLBfuddwnihiSLb.dll
		$a_01_7 = {77 44 53 44 70 65 48 68 4a 5a 48 48 6c 75 6b 59 76 4a 46 76 49 62 7a 6c 46 45 7a 2e 64 6c 6c } //1 wDSDpeHhJZHHlukYvJFvIbzlFEz.dll
		$a_01_8 = {51 72 55 72 77 74 50 63 6e 78 78 6b 77 6e 78 61 6c 67 7a 4a 50 57 56 46 67 54 6c 54 2e 64 6c 6c } //1 QrUrwtPcnxxkwnxalgzJPWVFgTlT.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}