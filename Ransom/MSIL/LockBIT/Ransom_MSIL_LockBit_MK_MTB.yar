
rule Ransom_MSIL_LockBit_MK_MTB{
	meta:
		description = "Ransom:MSIL/LockBit.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 5d 00 00 70 11 04 28 1d 00 00 0a 73 1e 00 00 0a 13 0b 11 0b 73 1f 00 00 0a 13 0c 11 0c 72 5d 00 00 70 6f 20 00 00 0a 11 0c 16 6f 21 00 00 0a 11 0c } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}