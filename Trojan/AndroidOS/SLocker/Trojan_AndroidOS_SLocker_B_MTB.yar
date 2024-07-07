
rule Trojan_AndroidOS_SLocker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SLocker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 54 66 0a 00 54 66 0d 00 6e 10 25 00 06 00 0c 06 72 10 1c 00 06 00 0c 06 1a 07 90 01 01 00 6e 20 4a 00 76 00 0a 06 38 06 3e 00 07 06 54 66 0a 00 54 66 0f 00 07 07 54 77 0a 00 54 77 0e 00 72 20 23 00 76 00 22 06 08 00 07 6d 07 d6 07 d7 07 08 54 88 0a 00 54 88 0c 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}