
rule Trojan_BAT_BitRAT_ABGY_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.ABGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 0b 11 02 6f ?? ?? ?? 0a 1e 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 38 ?? ?? ?? 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 13 03 38 ?? ?? ?? ff 11 01 11 02 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 09 } //2
		$a_01_1 = {4f 00 6d 00 69 00 6e 00 64 00 61 00 6a 00 6e 00 77 00 74 00 79 00 67 00 6b 00 67 00 67 00 66 00 6c 00 6d 00 75 00 6c 00 67 00 79 00 } //1 Omindajnwtygkggflmulgy
		$a_01_2 = {49 00 66 00 65 00 63 00 65 00 79 00 79 00 79 00 } //1 Ifeceyyy
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}