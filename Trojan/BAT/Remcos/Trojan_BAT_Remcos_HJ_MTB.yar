
rule Trojan_BAT_Remcos_HJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4e 42 43 42 43 58 4e 42 4e 43 42 4e 43 42 4d 42 4e 43 58 4e 43 58 4e 43 4e 58 42 43 4e 42 58 } //1 NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX
		$a_81_1 = {44 53 44 47 53 47 44 53 53 } //1 DSDGSGDSS
		$a_81_2 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 64 58 47 63 49 4c 2f 62 62 64 64 6c 6c 2e 74 78 74 } //1 transfer.sh/get/dXGcIL/bbddll.txt
		$a_81_3 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 78 77 59 41 30 43 2f 63 68 2e 74 78 74 } //1 transfer.sh/get/xwYA0C/ch.txt
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}