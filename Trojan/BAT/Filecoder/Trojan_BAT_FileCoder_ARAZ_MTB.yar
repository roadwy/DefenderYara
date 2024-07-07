
rule Trojan_BAT_FileCoder_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 43 6f 6e 74 69 2e 70 64 62 } //2 \Conti.pdb
		$a_01_1 = {5f 5f 44 45 43 52 59 50 54 5f 4e 4f 54 45 5f 5f } //2 __DECRYPT_NOTE__
		$a_80_2 = {43 4f 4e 54 49 5f 4c 4f 47 2e 74 78 74 } //CONTI_LOG.txt  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}