
rule Trojan_AndroidOS_Badpack_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Badpack.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {14 00 41 14 00 00 14 01 b5 db ff ff 90 00 00 01 94 00 00 01 3d 00 1a 00 14 00 69 2c 00 00 14 01 14 f6 ff ff 91 01 00 01 90 01 00 01 94 00 01 01 } //1
		$a_01_1 = {14 09 86 c5 08 00 71 30 db 00 99 09 0a 09 35 98 0f 00 21 59 35 98 0c 00 48 09 05 08 d7 99 18 00 8d 99 4f 09 05 08 d8 08 08 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}