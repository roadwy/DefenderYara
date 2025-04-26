
rule Trojan_AndroidOS_Banker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 09 36 00 d1 73 11 24 48 07 02 09 d0 55 d0 1a dc 0a 09 03 48 0a 01 0a 14 0b 99 90 00 00 93 0c 03 05 b0 cb 91 0c 05 0b b0 3c da 0c 0c 00 b0 7c 93 07 03 03 db 07 07 01 df 07 07 01 b0 7c b4 33 b0 3c 97 03 0c 0a 8d 33 4f 03 06 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}