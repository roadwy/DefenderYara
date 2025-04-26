
rule Trojan_BAT_RedLine_KAV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {33 36 39 62 30 30 37 37 2d 61 66 35 35 2d 34 33 37 61 2d 39 39 66 35 2d 34 66 33 39 33 39 37 30 30 64 32 64 } //369b0077-af55-437a-99f5-4f3939700d2d  1
		$a_80_1 = {4c 6f 67 69 74 65 63 68 20 47 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //Logitech G Innovations Trademark  1
		$a_80_2 = {4c 6f 67 69 74 65 63 68 20 47 20 70 72 6f 66 65 73 73 69 6f 6e 61 6c 20 67 61 6d 69 6e 67 20 6b 65 79 62 6f 61 72 64 73 20 61 72 65 20 64 65 73 69 67 6e 65 64 20 66 6f 72 20 63 6f 6d 70 65 74 69 74 69 6f 6e } //Logitech G professional gaming keyboards are designed for competition  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}