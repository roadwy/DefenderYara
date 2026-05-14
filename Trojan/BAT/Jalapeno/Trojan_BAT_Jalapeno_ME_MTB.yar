
rule Trojan_BAT_Jalapeno_ME_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 0c 08 8e b7 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 0d 07 09 16 09 8e b7 6f ?? 00 00 0a 07 08 16 08 8e b7 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 16 07 6f ?? 00 00 0a b7 16 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 14 6f ?? 00 00 0a 26 } //5
		$a_03_1 = {16 7e 0b 00 00 04 12 01 73 ?? 00 00 0a 80 ?? 00 00 04 07 0a de } //2
		$a_03_2 = {7e 0c 00 00 04 20 e8 03 00 00 d8 28 ?? 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=8
 
}