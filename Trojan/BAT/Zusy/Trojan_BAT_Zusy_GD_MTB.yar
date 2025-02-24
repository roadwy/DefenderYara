
rule Trojan_BAT_Zusy_GD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 } //2
		$a_01_1 = {7e 01 00 00 04 8e 69 8d 16 00 00 01 0a 16 13 07 } //1
		$a_01_2 = {46 73 69 67 6e 61 74 75 72 65 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 Fsignature.compressed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}