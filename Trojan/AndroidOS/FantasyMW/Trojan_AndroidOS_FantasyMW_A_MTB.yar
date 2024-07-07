
rule Trojan_AndroidOS_FantasyMW_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FantasyMW.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 46 61 6e 74 61 73 79 4d 61 6c 77 61 72 65 2f } //1 /FantasyMalware/
		$a_00_1 = {4c 63 6f 6d 2f 61 70 70 6c 65 2f 66 61 6e 74 61 73 74 69 63 2f 62 61 6e 6b 65 72 73 } //1 Lcom/apple/fantastic/bankers
		$a_00_2 = {4c 63 6f 6d 2f 61 70 70 6c 65 2f 66 61 6e 74 61 73 74 69 63 2f 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } //1 Lcom/apple/fantastic/communication
		$a_00_3 = {67 65 74 52 6f 6f 74 49 6e 41 63 74 69 76 65 57 69 6e 64 6f 77 } //1 getRootInActiveWindow
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}