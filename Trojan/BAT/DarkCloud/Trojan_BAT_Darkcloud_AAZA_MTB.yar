
rule Trojan_BAT_Darkcloud_AAZA_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.AAZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 28 19 00 00 0a 25 26 0b } //2
		$a_03_1 = {06 13 04 1a 2b b9 28 ?? 00 00 06 28 ?? 00 00 0a 0c 2b e8 26 1c 17 2d a7 26 11 04 0d 1e 16 2c 9f } //2
		$a_03_2 = {06 25 26 20 00 01 00 00 14 14 09 28 ?? 00 00 06 6f ?? 00 00 0a 25 26 26 } //2
		$a_01_3 = {77 66 65 31 6e 51 79 73 4c 41 70 69 6b 46 67 4f 46 47 2e 66 78 43 68 50 69 64 59 39 32 41 5a 57 32 62 53 47 77 } //1 wfe1nQysLApikFgOFG.fxChPidY92AZW2bSGw
		$a_01_4 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}