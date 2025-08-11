
rule Trojan_Linux_MsfwRevShell_NF_{
	meta:
		description = "Trojan:Linux/MsfwRevShell.NF!!MsfwRevShell.gen!NF,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 03 5e 6a 21 58 ff ce 0f 05 e0 ?? 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 54 5f 0f 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}