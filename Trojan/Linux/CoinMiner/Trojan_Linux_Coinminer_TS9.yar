
rule Trojan_Linux_Coinminer_TS9{
	meta:
		description = "Trojan:Linux/Coinminer.TS9,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {78 00 6d 00 72 00 [0-08] 2e 00 6b 00 72 00 79 00 70 00 74 00 65 00 78 00 2e 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}