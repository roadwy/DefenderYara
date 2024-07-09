
rule Trojan_BAT_Bsymem_ADA_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 16 0c 2b 17 06 08 8f ?? 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 17 59 32 e1 } //10
		$a_80_1 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } ///c taskkill /im  3
		$a_80_2 = {2e 65 78 65 22 20 2f 66 20 26 20 65 72 61 73 65 } //.exe" /f & erase  3
		$a_80_3 = {43 68 65 63 6b 46 69 6c 65 } //CheckFile  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}