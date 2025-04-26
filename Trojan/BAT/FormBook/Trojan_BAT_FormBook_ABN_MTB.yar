
rule Trojan_BAT_FormBook_ABN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0a 20 00 32 ?? 00 8d ?? ?? ?? 01 0b 28 ?? ?? ?? 06 0c 16 0d 2b 50 00 16 13 04 2b 31 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 28 ?? ?? ?? 0a 9c 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d bf } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 00 } //1 Y5tFvU8EY
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}