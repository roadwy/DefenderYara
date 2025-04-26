
rule Trojan_Win32_Sushta_Mt{
	meta:
		description = "Trojan:Win32/Sushta.Mt,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-ff] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-ff] 2f 00 74 00 72 00 [0-ff] 6d 00 73 00 68 00 74 00 61 00 [0-ff] 68 00 74 00 74 00 70 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}