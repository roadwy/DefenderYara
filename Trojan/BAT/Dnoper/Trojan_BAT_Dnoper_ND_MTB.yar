
rule Trojan_BAT_Dnoper_ND_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 20 00 00 0a 72 25 00 00 70 6f ?? 00 00 0a 0a 06 72 99 00 00 70 17 8c 31 00 00 01 1a 6f ?? 00 00 0a 00 28 1a 00 00 0a 72 b7 00 00 70 28 1b 00 00 0a } //3
		$a_01_1 = {69 72 6d 65 6e 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 irmeni.Properties.Resources.resources
		$a_01_2 = {4b 69 6d 79 61 5f 44 65 } //1 Kimya_De
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}