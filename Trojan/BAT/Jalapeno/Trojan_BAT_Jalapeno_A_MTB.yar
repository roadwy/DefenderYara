
rule Trojan_BAT_Jalapeno_A_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 00 40 01 00 8d 84 00 00 01 0a 38 09 00 00 00 03 06 16 07 6f 26 01 00 0a 02 06 16 06 8e 69 6f 27 01 00 0a 25 0b 3a e5 ff ff ff } //5
		$a_03_1 = {8d 84 00 00 01 0d 73 da 00 00 0a 09 ?? ?? ?? ?? ?? 08 8e 69 09 8e 69 58 8d 84 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}