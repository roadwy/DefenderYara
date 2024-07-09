
rule Trojan_Win32_TrickBotCrypt_FO_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8a 04 08 32 04 16 } //5
		$a_03_1 = {03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 8b 45 ?? 03 c8 03 cb 03 cf 03 ce 03 ca 8b 55 d0 03 55 0c 8a 45 eb 88 04 0a e9 } //5
		$a_81_2 = {6e 43 48 54 62 4f 32 4c 65 41 44 76 2b 34 64 3c 6d 37 79 28 39 25 70 75 64 71 3e 31 64 7a 55 56 31 72 68 37 30 54 32 63 44 36 24 48 4b 77 63 55 47 46 52 4e 72 44 31 2b 6e 48 39 50 45 24 39 50 73 6f 6d 4c 73 56 69 68 29 67 } //10 nCHTbO2LeADv+4d<m7y(9%pudq>1dzUV1rh70T2cD6$HKwcUGFRNrD1+nH9PE$9PsomLsVih)g
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*10) >=10
 
}