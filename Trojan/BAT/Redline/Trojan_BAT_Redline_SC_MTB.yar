
rule Trojan_BAT_Redline_SC_MTB{
	meta:
		description = "Trojan:BAT/Redline.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 28 ?? ?? ?? 06 13 04 38 ?? ?? ?? ?? 73 ?? ?? ?? 0a 13 03 38 ?? ?? ?? ?? 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 } //10
		$a_01_1 = {54 00 35 00 41 00 41 00 5a 00 } //1 T5AAZ
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {46 00 61 00 62 00 72 00 61 00 6b 00 61 00 } //1 Fabraka
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}