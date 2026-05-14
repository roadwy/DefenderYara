
rule Trojan_BAT_Jalapeno_BAN_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 ?? ?? 00 00 0a 17 73 11 00 00 0a 13 04 38 00 00 00 00 00 11 04 02 16 02 8e 69 ?? ?? 00 00 0a 38 2e 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0b 00 fe 0c 0b 00 45 01 00 00 00 39 00 00 00 fe 0c 0b 00 20 dc 03 00 00 3b e5 ff ff ff 38 26 00 00 00 11 04 ?? ?? 00 00 0a 20 00 00 00 00 7e 53 00 00 04 7b 30 00 00 04 3a c9 ff ff ff 26 20 06 00 00 00 38 be ff ff ff 11 06 ?? ?? 00 00 0a 13 05 38 00 00 00 00 dd 5f 01 00 00 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}