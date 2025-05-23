
rule Trojan_BAT_FileCoder_PN_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 06 16 11 07 6f ?? 00 00 0a 08 11 06 16 20 ?? 20 00 00 6f ?? 00 00 0a 25 13 07 16 30 e0 11 04 6f ?? 00 00 0a 72 e4 05 00 70 02 72 56 07 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a de 0c } //2
		$a_01_1 = {57 00 68 00 61 00 74 00 20 00 64 00 6f 00 20 00 49 00 20 00 68 00 61 00 76 00 65 00 20 00 74 00 6f 00 20 00 64 00 6f 00 20 00 74 00 6f 00 20 00 62 00 72 00 65 00 61 00 6b 00 20 00 74 00 68 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //2 What do I have to do to break the encryption
		$a_01_2 = {74 00 68 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 } //1 the encryption will be removed
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}