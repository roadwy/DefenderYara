
rule Trojan_Win32_TrickBotCrypt_FN_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 75 ec 03 f2 2b f1 90 00 } //5
		$a_01_1 = {8b 4d 0c 88 04 31 e9 } //5
		$a_81_2 = {25 2b 74 44 4b 56 52 25 33 71 25 2a 26 66 42 53 21 49 72 73 3c 26 45 66 3e 72 30 3f 68 44 37 35 5f 74 6f 51 25 79 43 64 6a 66 30 42 78 50 24 31 28 43 49 74 71 54 55 40 32 76 37 25 61 6a 6b 51 6b 4f 32 55 74 4f 50 30 5f 49 77 50 3c 3e 6a 79 5e 61 6b 26 30 34 } //10 %+tDKVR%3q%*&fBS!Irs<&Ef>r0?hD75_toQ%yCdjf0BxP$1(CItqTU@2v7%ajkQkO2UtOP0_IwP<>jy^ak&04
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*10) >=10
 
}