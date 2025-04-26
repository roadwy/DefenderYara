
rule Trojan_BAT_Spy_JLNG_MTB{
	meta:
		description = "Trojan:BAT/Spy.JLNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 } //2 transfer.sh/get
		$a_81_1 = {52 65 70 6c 61 63 65 } //2 Replace
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //2 InvokeMember
		$a_01_4 = {4e 00 42 00 43 00 42 00 43 00 58 00 4e 00 42 00 4e 00 43 00 42 00 4e 00 43 00 42 00 4d 00 42 00 4e 00 43 00 58 00 4e 00 43 00 58 00 4e 00 43 00 4e 00 58 00 42 00 43 00 4e 00 42 00 58 00 } //2 NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX
		$a_81_5 = {47 65 74 54 79 70 65 } //2 GetType
		$a_01_6 = {53 00 6b 00 69 00 64 00 6f 00 6d 00 6f 00 6e 00 65 00 79 00 2e 00 4d 00 6f 00 6e 00 65 00 79 00 } //2 Skidomoney.Money
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_01_4  & 1)*2+(#a_81_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}