
rule Trojan_AndroidOS_Badpack_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Badpack.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {da 11 0f 08 99 04 10 11 8d 44 48 10 07 0c 97 04 04 10 8d 44 4f 04 07 0c d8 08 08 01 00 00 d8 0c 0c 01 12 04 28 df } //2
		$a_00_1 = {e2 04 03 08 e0 05 03 18 b6 54 b0 14 44 05 06 00 97 03 04 05 e0 04 01 03 e2 05 01 1d b6 54 97 01 04 03 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}