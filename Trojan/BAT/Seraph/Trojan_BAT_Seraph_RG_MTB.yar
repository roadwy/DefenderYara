
rule Trojan_BAT_Seraph_RG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {46 75 6c 6c 49 6e 66 6f 53 65 6e 64 65 72 } //1 FullInfoSender
		$a_01_1 = {41 6c 6c 57 61 6c 6c 65 74 73 } //1 AllWallets
		$a_01_2 = {52 6f 73 43 6f 6d 4e 61 64 7a 6f 72 } //1 RosComNadzor
		$a_01_3 = {61 64 6b 61 73 64 38 75 33 68 62 61 73 64 } //1 adkasd8u3hbasd
		$a_01_4 = {6b 61 73 64 69 68 62 66 70 66 64 75 71 77 } //1 kasdihbfpfduqw
		$a_01_5 = {73 64 66 6b 38 33 68 6b 61 73 64 } //1 sdfk83hkasd
		$a_01_6 = {61 73 64 61 69 64 39 68 32 34 6b 61 73 64 } //1 asdaid9h24kasd
		$a_01_7 = {64 76 73 6a 69 6f 68 71 33 } //1 dvsjiohq3
		$a_01_8 = {62 6c 76 6e 7a 63 77 71 65 } //1 blvnzcwqe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}