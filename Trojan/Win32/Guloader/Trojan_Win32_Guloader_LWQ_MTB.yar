
rule Trojan_Win32_Guloader_LWQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {62 72 74 73 65 6a 6c 61 64 73 2e 66 69 63 } //1 brtsejlads.fic
		$a_81_1 = {6d 65 74 65 6d 70 73 79 63 68 6f 73 69 7a 65 2e 63 6f 74 } //1 metempsychosize.cot
		$a_81_2 = {65 6b 73 61 6d 69 6e 61 74 6f 72 73 20 61 75 74 6f 72 69 74 61 74 69 76 65 72 65 20 6d 69 6e 6f 6e 61 } //1 eksaminators autoritativere minona
		$a_81_3 = {6d 69 6e 69 73 75 72 76 65 79 73 2e 65 78 65 } //1 minisurveys.exe
		$a_81_4 = {6b 62 73 74 61 64 62 6f 65 72 73 20 74 69 6c 6d 61 61 6c 69 6e 67 20 68 6f 6e 6f 72 72 } //1 kbstadboers tilmaaling honorr
		$a_81_5 = {6b 6f 6e 74 72 61 64 69 6b 74 69 6f 6e 65 72 73 20 6d 65 72 63 75 72 69 61 6c 69 74 79 20 63 61 74 65 63 68 69 73 74 73 } //1 kontradiktioners mercuriality catechists
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}