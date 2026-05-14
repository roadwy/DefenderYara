
rule Trojan_Win32_Guloader_SWBI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SWBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6e 64 65 73 63 65 6e 74 32 30 36 5c 42 72 75 6e 69 7a 65 6d } //2 Frondescent206\Brunizem
		$a_81_1 = {62 61 6a 6f 6e 65 74 6c 61 61 73 65 6e 65 73 2e 6c 61 6d } //1 bajonetlaasenes.lam
		$a_81_2 = {49 6d 70 72 65 73 73 69 6f 6e 61 6c 6c 79 2e 74 78 74 } //1 Impressionally.txt
		$a_81_3 = {55 6e 65 6d 70 69 72 69 63 61 6c 39 32 2e 69 6e 69 } //1 Unempirical92.ini
		$a_81_4 = {62 79 64 65 6d 61 61 64 65 72 6e 65 2e 6a 70 67 } //1 bydemaaderne.jpg
		$a_81_5 = {42 61 6e 64 6f 6c 65 72 65 74 2e 6a 70 67 } //1 Bandoleret.jpg
		$a_81_6 = {43 61 74 65 72 63 6f 75 73 69 6e 2e 74 78 74 } //1 Catercousin.txt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}