
rule Ransom_MacOS_Mabouia_A_MTB{
	meta:
		description = "Ransom:MacOS/Mabouia.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 69 76 65 63 6f 64 65 2e 63 6f 6d 2e 62 72 } //1 creativecode.com.br
		$a_00_1 = {6d 61 62 6f 75 69 61 5f 44 65 63 72 79 70 74 65 72 } //1 mabouia_Decrypter
		$a_00_2 = {2f 44 65 73 6b 74 6f 70 2f 72 61 6e 73 6f 6d } //1 /Desktop/ransom
		$a_00_3 = {2f 6d 61 62 6f 75 69 61 2f 63 61 74 63 68 65 72 2e 70 68 70 } //1 /mabouia/catcher.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}