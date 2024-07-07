
rule Trojan_Win64_IcedID_ASV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ASV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {42 75 6a 51 52 47 76 6b 56 61 6e 73 } //BujQRGvkVans  3
		$a_80_1 = {44 63 5a 6d 50 45 68 47 44 49 64 61 50 6f 70 69 6e 51 } //DcZmPEhGDIdaPopinQ  3
		$a_80_2 = {46 6d 66 6f 6c 4f 58 51 4e 61 44 45 64 53 72 55 4e 43 } //FmfolOXQNaDEdSrUNC  3
		$a_80_3 = {48 41 46 79 6e 51 5a 71 72 49 } //HAFynQZqrI  3
		$a_80_4 = {49 64 79 54 51 70 75 62 51 42 4b 62 45 } //IdyTQpubQBKbE  3
		$a_80_5 = {4d 78 6d 4c 67 6c 75 54 51 } //MxmLgluTQ  3
		$a_80_6 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
		$a_80_7 = {53 77 69 74 63 68 54 6f 54 68 72 65 61 64 } //SwitchToThread  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}