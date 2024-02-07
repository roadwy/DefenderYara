
rule Trojan_Win32_EmotetCrypt_DE_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c1 03 0f af 0d 90 01 04 03 c8 8b 44 24 14 03 ca 03 d9 8a 0c 33 8a 18 32 d9 8b 4c 24 24 88 18 8b 44 24 10 40 3b c1 89 44 24 10 0f 82 90 00 } //01 00 
		$a_81_1 = {6e 43 3f 4c 71 34 3f 78 5f 30 74 79 53 6c 78 51 23 35 6b 38 43 58 5f 4e 40 43 55 52 34 35 52 25 77 31 2b 64 5a 34 2a 3e 58 54 36 52 6c 3c 75 78 23 36 6a 42 4d 39 26 3f 31 38 70 34 36 26 3f 28 65 52 46 5e 55 5e 6c 6a 76 77 4d 6e 4d 66 49 25 76 29 4a 6d 4b 55 29 2b 3c 63 53 36 21 76 6f 53 28 } //00 00  nC?Lq4?x_0tySlxQ#5k8CX_N@CUR45R%w1+dZ4*>XT6Rl<ux#6jBM9&?18p46&?(eRF^U^ljvwMnMfI%v)JmKU)+<cS6!voS(
	condition:
		any of ($a_*)
 
}