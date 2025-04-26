
rule Trojan_BAT_Seraph_MBZB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.MBZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {14 0b 28 0c 00 00 06 0b 06 07 28 01 00 00 2b 28 02 00 00 2b 16 07 8e 69 } //1
		$a_01_1 = {49 53 68 61 70 65 00 43 69 72 63 6c 65 00 52 65 73 6f 75 72 63 65 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}