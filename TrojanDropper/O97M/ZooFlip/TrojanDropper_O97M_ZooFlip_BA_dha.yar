
rule TrojanDropper_O97M_ZooFlip_BA_dha{
	meta:
		description = "TrojanDropper:O97M/ZooFlip.BA!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 69 6e 36 34 [0-07] 77 69 6e 33 32 [0-20] 76 62 61 37 } //1
		$a_01_1 = {64 78 61 73 6c 6f 6e 67 64 79 61 73 6c 6f 6e 67 64 78 73 61 73 6c 6f 6e 67 64 79 73 61 73 6c 6f 6e 67 64 78 63 63 61 73 6c 6f 6e 67 64 79 63 63 61 73 6c 6f 6e 67 64 66 61 61 73 6c 6f 6e 67 64 66 61 73 6c 6f 6e 67 77 73 77 61 73 69 6e 74 65 67 65 72 } //1 dxaslongdyaslongdxsaslongdysaslongdxccaslongdyccaslongdfaaslongdfaslongwswasinteger
		$a_03_2 = {63 72 65 61 74 65 70 72 6f 63 65 73 73 77 22 28 5f 62 79 76 61 6c 6c 61 6e 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 6c 63 6c 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 6c 70 61 73 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 6c 74 61 73 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 62 69 68 73 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 64 63 66 73 61 73 6c 6f 6e 67 [0-03] 2c 5f 62 79 76 61 6c 6c 65 61 73 6c 6f 6e 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}