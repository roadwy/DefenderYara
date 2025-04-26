
rule Backdoor_BAT_Crysan_ABR_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_03_0 = {2b 03 00 2b 07 6f 07 ?? ?? 0a 2b f6 00 de 11 08 2b 08 08 6f 08 ?? ?? 0a 2b 04 2c 03 2b f4 00 dc 90 0a 40 00 00 02 73 03 ?? ?? 0a 0a 00 73 04 ?? ?? 0a 0b 00 06 16 73 05 ?? ?? 0a 73 06 ?? ?? 0a 0c 00 08 07 } //5
		$a_01_1 = {50 61 73 73 77 6f 72 64 52 65 73 74 72 69 63 74 69 6f 6e } //1 PasswordRestriction
		$a_01_2 = {56 69 72 75 73 49 6e 66 65 63 74 65 64 } //1 VirusInfected
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
		$a_01_6 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_7 = {44 65 62 75 67 67 65 72 } //1 Debugger
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}