
rule Trojan_BAT_NjRat_PSA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 06 00 00 04 d0 01 ?? ?? ?? 28 14 ?? ?? ?? 6f 15 ?? ?? ?? 2c 20 72 01 00 00 70 16 8d 15 00 00 01 28 16 ?? ?? ?? 73 17 ?? ?? ?? 7a 73 18 ?? ?? ?? 80 06 00 00 04 7e 06 00 00 04 d0 01 ?? ?? ?? 28 14 ?? ?? ?? 14 6f 19 ?? ?? ?? 28 01 00 00 2b 0a de 6c } //5
		$a_01_1 = {53 74 72 61 6e 67 65 43 52 43 } //1 StrangeCRC
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {6b 5a 5a 41 49 41 4f 35 59 6a 6f 4c 52 49 41 55 64 77 } //1 kZZAIAO5YjoLRIAUdw
		$a_01_5 = {4c 49 4c 5a 79 52 75 6d 59 67 50 57 61 6b 63 36 49 79 } //1 LILZyRumYgPWakc6Iy
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}