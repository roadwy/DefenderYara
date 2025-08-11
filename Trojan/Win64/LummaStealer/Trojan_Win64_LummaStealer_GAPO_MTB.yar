
rule Trojan_Win64_LummaStealer_GAPO_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 a8 63 c8 37 1f 1d 05 6f c0 fc d8 ed a5 4e ee cd f0 2f f7 11 99 da 13 53 d9 24 f9 f9 b8 9e 1e fd e0 f0 19 83 9d 13 cf 4d b3 c6 0a fc 8a 92 53 c4 0a 76 fa 40 59 4a db 82 e6 7d 1e 72 4f 7c 61 } //8
		$a_01_1 = {2e 65 79 65 } //1 .eye
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*1) >=9
 
}