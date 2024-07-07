
rule Trojan_BAT_RedLine_RDCF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 6f 75 63 68 6f 72 72 75 6d 6d 61 67 79 } //1 Vouchorrummagy
		$a_01_1 = {64 6f 72 61 79 43 61 74 68 61 } //1 dorayCatha
		$a_01_2 = {64 6f 72 61 79 45 76 65 6e 73 } //1 dorayEvens
		$a_01_3 = {63 61 74 68 61 42 61 6e 64 61 72 } //1 cathaBandar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}