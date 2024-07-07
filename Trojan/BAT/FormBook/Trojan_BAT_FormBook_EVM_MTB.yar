
rule Trojan_BAT_FormBook_EVM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 41 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1 䄀彟彟彟彟彟_
		$a_01_1 = {00 42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1
		$a_01_2 = {00 43 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1
		$a_01_3 = {00 45 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1 䔀彟彟彟彟彟彟彟彟_
		$a_01_4 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //1 䌀敲瑡䥥獮慴据e
		$a_01_5 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_6 = {00 43 6f 6e 73 74 72 75 63 74 69 6f 6e 43 61 6c 6c 00 } //1 䌀湯瑳畲瑣潩䍮污l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}