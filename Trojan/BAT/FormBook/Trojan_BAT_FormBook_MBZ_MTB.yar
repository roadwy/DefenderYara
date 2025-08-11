
rule Trojan_BAT_FormBook_MBZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 74 65 63 4e 65 77 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 } //4 EtecNews.Properties.Resources.resourc
		$a_01_1 = {74 00 65 00 63 00 4e 00 65 00 77 00 73 00 00 1d 43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 } //6
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*6) >=10
 
}