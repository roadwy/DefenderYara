
rule Trojan_BAT_ClipBanker_GAF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {74 65 74 68 65 72 73 6f 6c } //tethersol  2
		$a_80_1 = {50 72 6f 63 65 73 73 43 6c 69 70 62 6f 61 72 64 43 6f 6e 74 65 6e 74 } //ProcessClipboardContent  1
		$a_80_2 = {43 6c 69 70 62 6f 61 72 64 4c 69 73 74 65 6e 65 72 } //ClipboardListener  1
		$a_80_3 = {5e 28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$  1
		$a_80_4 = {5e 28 3f 3a 5b 4c 4d 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 29 24 } //^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$  1
		$a_80_5 = {28 3f 3a 5e 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 29 } //(?:^0x[a-fA-F0-9]{40}$)  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=7
 
}