
rule Trojan_BAT_Injuke_PSBF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {28 62 00 00 0a 00 72 53 46 00 70 28 6e ?? ?? ?? 28 28 ?? ?? ?? 5b 58 00 23 00 00 00 00 50 48 f5 40 23 00 00 00 00 60 60 dc 40 28 67 ?? ?? ?? 59 28 62 ?? ?? ?? 00 72 c5 46 00 70 28 6e ?? ?? ?? 28 28 ?? ?? ?? 5b 58 5a 8d 5f 00 00 01 0a 7e 29 ?? ?? ?? 28 ba ?? ?? ?? 0b 7e 2a ?? ?? ?? 07 06 28 e5 ?? ?? ?? de 0f 07 2c 0b 7e 2b ?? ?? ?? 07 28 d2 ?? ?? ?? dc 06 2a } //5
		$a_01_1 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_4 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}