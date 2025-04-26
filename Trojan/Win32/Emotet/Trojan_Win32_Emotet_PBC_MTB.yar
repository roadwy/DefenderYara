
rule Trojan_Win32_Emotet_PBC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 33 0f b6 04 37 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 0c 28 8b 44 24 ?? 8a 14 32 32 d1 88 55 00 } //1
		$a_81_1 = {6e 79 67 4e 65 46 54 7d 64 46 38 7e 67 34 77 76 68 39 79 65 40 46 4d 41 67 4e 6d 53 39 34 3f 53 6b 46 62 37 4f 38 65 58 5a 6e 77 3f 33 62 79 7c 6a 7e 32 4c 42 43 4e 52 32 45 6a 6f 4d 6e 67 68 47 32 41 7e 5a 7d 76 33 47 58 61 } //1 nygNeFT}dF8~g4wvh9ye@FMAgNmS94?SkFb7O8eXZnw?3by|j~2LBCNR2EjoMnghG2A~Z}v3GXa
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}