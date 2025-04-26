
rule Trojan_BAT_Zusy_HNK_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_80_0 = {59 57 31 7a 61 53 35 6b 62 47 77 3d } //YW1zaS5kbGw=  5
		$a_80_1 = {51 57 31 7a 61 56 4e 6a 59 57 35 43 64 57 5a 6d 5a 58 49 3d } //QW1zaVNjYW5CdWZmZXI=  5
		$a_01_2 = {00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 } //1 䜀瑥牐捯摁牤獥s
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}