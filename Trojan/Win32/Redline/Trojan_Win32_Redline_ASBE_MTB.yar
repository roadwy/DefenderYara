
rule Trojan_Win32_Redline_ASBE_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 83 c4 ?? 46 3b f7 0f 82 } //1
		$a_03_1 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 6a 6f 68 } //1
		$a_01_2 = {44 53 75 79 67 61 63 } //2 DSuygac
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}
rule Trojan_Win32_Redline_ASBE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ASBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {01 f8 03 70 0c 8d 85 [0-04] 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c ff 15 } //4
		$a_01_1 = {75 6f 79 77 78 70 79 72 7a 69 6c 75 68 6e 71 77 6e 65 79 72 76 6b 64 6e 6c 66 72 69 7a 75 62 61 63 64 68 78 68 61 68 6f 6d 63 6b 62 76 75 68 6c 62 65 64 70 6f 63 71 6c 78 66 78 6e 6b 77 64 76 6e 64 6a 6f 77 63 68 66 72 64 78 6f 6f 66 77 77 74 63 74 6e 7a 75 61 67 } //1 uoywxpyrziluhnqwneyrvkdnlfrizubacdhxhahomckbvuhlbedpocqlxfxnkwdvndjowchfrdxoofwwtctnzuag
		$a_01_2 = {6c 6f 77 72 6d 6e 6c 73 6a 75 76 6e 74 66 64 74 6c 70 65 63 76 64 6b 7a 75 68 79 73 70 75 6b 70 64 72 68 78 64 73 6a 74 } //1 lowrmnlsjuvntfdtlpecvdkzuhyspukpdrhxdsjt
		$a_01_3 = {69 6c 79 6a 68 69 79 70 72 61 74 70 61 69 79 79 6b 66 70 67 66 68 6a 6f 6a 68 76 75 72 } //1 ilyjhiypratpaiyykfpgfhjojhvur
		$a_01_4 = {76 69 71 72 6a 7a 61 6e 6b 6f 62 6d 74 64 77 75 65 73 62 72 77 6e 6a 67 67 68 78 63 6a 6c 6d 75 77 66 68 6b 71 71 77 6b 72 70 67 7a 6d 6a 73 6c 67 64 6e 6f 6e } //1 viqrjzankobmtdwuesbrwnjgghxcjlmuwfhkqqwkrpgzmjslgdnon
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}