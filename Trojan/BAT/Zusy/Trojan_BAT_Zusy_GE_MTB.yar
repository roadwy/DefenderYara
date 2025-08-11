
rule Trojan_BAT_Zusy_GE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 } //2
		$a_02_1 = {7e 01 00 00 04 8e 69 8d ?? 00 00 01 0a 16 13 07 } //2
		$a_01_2 = {46 73 69 67 6e 61 74 75 72 65 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 Fsignature.compressed
		$a_01_3 = {70 66 78 2e 73 74 72 6f 6e 67 6e 61 6d 65 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 pfx.strongname.compressed
		$a_01_4 = {70 66 78 2e 73 74 67 6e 61 6d 65 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 pfx.stgname.compressed
		$a_01_5 = {63 72 74 2e 70 66 78 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 crt.pfx.compressed
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}