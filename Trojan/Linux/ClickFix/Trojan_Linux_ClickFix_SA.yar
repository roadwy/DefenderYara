
rule Trojan_Linux_ClickFix_SA{
	meta:
		description = "Trojan:Linux/ClickFix.SA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 61 6c 6f 72 74 74 61 63 74 69 63 61 6c 2e 74 6f 70 2f } //1 salorttactical.top/
	condition:
		((#a_00_0  & 1)*1) >=1
 
}