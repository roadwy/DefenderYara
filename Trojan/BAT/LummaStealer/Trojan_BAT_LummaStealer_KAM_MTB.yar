
rule Trojan_BAT_LummaStealer_KAM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {36 66 38 61 66 36 39 64 2d 34 38 36 61 2d 34 63 64 36 2d 62 61 36 65 2d 38 33 61 65 38 35 62 62 63 30 36 30 } //6f8af69d-486a-4cd6-ba6e-83ae85bbc060  1
		$a_80_1 = {49 6e 74 65 6c 20 43 6f 72 65 20 49 6e 63 2e 20 54 72 61 64 65 6d 61 72 6b } //Intel Core Inc. Trademark  1
		$a_80_2 = {41 64 6a 65 63 74 69 76 65 73 20 77 68 69 63 68 20 77 69 6c 6c 20 72 61 6e 64 6f 6d 6c 79 20 61 70 70 65 61 72 20 77 69 74 68 20 61 20 63 6c 69 63 6b } //Adjectives which will randomly appear with a click  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}