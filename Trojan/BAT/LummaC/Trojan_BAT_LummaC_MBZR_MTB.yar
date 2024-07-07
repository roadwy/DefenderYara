
rule Trojan_BAT_LummaC_MBZR_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 62 6e 61 74 69 6f 6e 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 } //1
		$a_01_1 = {66 4a 68 69 73 75 41 49 55 4f 00 54 68 72 53 67 74 72 6a 79 74 00 52 65 6d 6f 74 65 4f 62 6a 65 } //1 䩦楨畳䥁何吀牨杓牴祪t敒潭整扏敪
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_LummaC_MBZR_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2b 03 17 2b 00 3a 90 01 01 00 00 00 06 6f 90 01 01 03 00 0a 11 06 6f 90 01 01 03 00 0a 16 73 58 03 00 0a 13 0d 11 0d 11 07 28 4f 18 00 06 de 14 11 0d 90 00 } //1
		$a_03_1 = {2b 21 02 7b 90 01 01 05 00 04 07 06 6f 90 01 03 0a 20 90 01 01 1d 1b be 20 90 01 01 35 de fb 58 20 90 01 01 6b 14 ed 61 6a 61 9f 07 20 a3 0c 4d c8 90 00 } //1
		$a_01_2 = {52 70 79 6f 69 64 70 66 2e } //5 Rpyoidpf.
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}