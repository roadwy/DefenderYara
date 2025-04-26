
rule Trojan_BAT_Jalapeno_ADBA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ADBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 3b 2b 40 2b 45 72 ?? ?? 03 70 2b 45 2b 4a 1d 2c 07 2b 48 14 2b 48 2c 03 2b 4b 7a 16 2d f0 17 2c ed d0 ?? 00 00 01 2b 44 06 72 ?? ?? 03 70 28 ?? 00 00 0a 80 ?? 00 00 04 16 2d d3 2a 28 ?? 00 00 0a 2b be 28 ?? ?? 00 06 2b b9 6f ?? 00 00 0a 2b b4 6f ?? 00 00 0a 2b b4 0a 2b b3 06 2b b5 28 ?? 00 00 0a 2b b1 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}