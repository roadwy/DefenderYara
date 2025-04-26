
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
rule Trojan_BAT_FileCoder_ARAZ_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 42 6c 61 63 6b 52 61 6e 73 6f 6d 77 61 72 65 46 69 72 65 65 79 65 2e 70 64 62 } //2 \BlackRansomwareFireeye.pdb
		$a_00_1 = {45 00 76 00 69 00 6c 00 42 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 46 00 6f 00 72 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 } //2 EvilBillingAddressForBitcoins
		$a_00_2 = {5c 00 76 00 69 00 63 00 74 00 69 00 6d 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //2 \victim\Desktop
		$a_00_3 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 6c 00 6f 00 73 00 74 00 } //2 Your files will be lost
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}