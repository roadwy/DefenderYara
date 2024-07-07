
rule Trojan_Linux_LMEMSE2E__LMEMSE2EMettlesploit{
	meta:
		description = "Trojan:Linux/LMEMSE2E!!LMEMSE2EMettlesploit,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 6d 65 6d 73 20 65 32 65 20 74 65 73 74 69 6e 67 20 73 69 67 20 66 6f 72 20 6d 65 74 74 6c 65 73 70 6c 6f 69 74 } //1 lmems e2e testing sig for mettlesploit
		$a_01_1 = {6d 65 74 74 6c 65 73 70 6c 6f 69 74 21 } //1 mettlesploit!
		$a_01_2 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 6d 65 74 74 6c 65 2e 63 } //1 /mettle/mettle/src/mettle.c
		$a_01_3 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 6d 61 69 6e 2e 63 } //1 /mettle/mettle/src/main.c
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}