
rule Trojan_BAT_LummaStealer_H_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 bd 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3e 00 00 00 82 00 00 00 d9 04 00 00 4a 05 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}