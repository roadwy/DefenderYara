
rule Trojan_BAT_FormBook_MVH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 14 00 00 04 73 40 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0a 73 42 00 00 0a 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 0c 73 44 00 00 0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a } //2
		$a_01_1 = {46 00 61 00 62 00 72 00 61 00 6b 00 61 00 } //1 Fabraka
		$a_01_2 = {54 00 35 00 41 00 41 00 5a 00 } //1 T5AAZ
		$a_01_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}