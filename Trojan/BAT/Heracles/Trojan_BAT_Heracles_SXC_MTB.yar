
rule Trojan_BAT_Heracles_SXC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {24 4d 79 42 69 67 46 61 74 43 72 69 74 69 63 61 6c 50 6f 69 6e 74 3d 5b 63 68 61 72 5d 36 35 2b 5b 63 68 61 72 5d 31 30 30 2b 5b 63 68 61 72 5d 31 30 30 2b 5b 63 68 61 72 5d 34 35 2b 5b 63 68 61 72 5d 37 37 2b 5b 63 68 61 72 5d 31 31 32 2b 5b 63 68 61 72 5d 38 30 2b 5b 63 68 61 72 5d 31 31 34 } //$MyBigFatCriticalPoint=[char]65+[char]100+[char]100+[char]45+[char]77+[char]112+[char]80+[char]114  1
		$a_80_1 = {5b 63 68 61 72 5d 31 30 31 2b 5b 63 68 61 72 5d 31 30 32 2b 5b 63 68 61 72 5d 31 30 31 2b 5b 63 68 61 72 5d 31 31 34 2b 5b 63 68 61 72 5d 31 30 31 2b 5b 63 68 61 72 5d 31 31 30 2b 5b 63 68 61 72 5d 39 39 2b 5b 63 68 61 72 5d 31 30 31 3b } //[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101;  1
		$a_80_2 = {24 73 3d 5b 63 68 61 72 5d 28 32 33 2b 32 33 29 2b 5b 63 68 61 72 5d 31 30 31 2b 5b 63 68 61 72 5d 31 32 30 2b 5b 63 68 61 72 5d 31 30 31 3b 26 28 24 4d 79 42 69 67 46 61 74 43 72 69 74 69 63 61 6c 50 6f 69 6e 74 29 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 24 73 20 2d 46 6f 72 63 65 } //$s=[char](23+23)+[char]101+[char]120+[char]101;&($MyBigFatCriticalPoint) -ExclusionExtension $s -Force  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}