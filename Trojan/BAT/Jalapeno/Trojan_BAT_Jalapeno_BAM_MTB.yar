
rule Trojan_BAT_Jalapeno_BAM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0b ?? ?? 00 00 0a 17 73 10 00 00 0a 13 08 38 00 00 00 00 00 11 08 02 16 02 8e 69 ?? ?? 00 00 0a 20 01 00 00 00 7e 2e 00 00 04 7b 10 00 00 04 3a 1d 00 00 00 26 20 00 00 00 00 38 12 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0a 00 fe 0c 0a 00 45 01 00 00 00 21 00 00 00 fe 0c 0a 00 20 dc 03 00 00 3b e5 ff ff ff 38 0e 00 00 00 11 09 ?? ?? 00 00 0a 13 05 38 0c 00 00 00 11 08 ?? ?? 00 00 0a 38 e6 ff ff ff dd 77 01 00 00 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}