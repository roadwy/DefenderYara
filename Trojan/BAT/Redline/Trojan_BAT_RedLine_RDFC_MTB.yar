
rule Trojan_BAT_RedLine_RDFC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 66 64 35 64 64 30 35 2d 30 63 31 32 2d 34 61 62 33 2d 39 31 31 63 2d 63 39 33 30 61 35 36 30 32 64 38 37 } //2 2fd5dd05-0c12-4ab3-911c-c930a5602d87
		$a_01_1 = {49 6e 74 65 6c 43 6f 72 65 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //1 IntelCore Innovations Trademark
		$a_01_2 = {70 72 6f 66 65 73 73 69 6f 6e 61 6c 20 67 61 6d 69 6e 67 20 6b 65 79 62 6f 61 72 64 73 20 61 72 65 20 64 65 73 69 67 6e 65 64 20 66 6f 72 20 63 6f 6d 70 65 74 69 74 69 6f 6e } //1 professional gaming keyboards are designed for competition
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}