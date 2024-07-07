
rule Trojan_Win32_Emotet_GR{
	meta:
		description = "Trojan:Win32/Emotet.GR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 54 69 71 5f 57 61 45 4e 5f 5f 79 39 46 38 39 7a 4c 75 6b 6a 6d 4d 2e 70 64 62 } //1 eTiq_WaEN__y9F89zLukjmM.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}