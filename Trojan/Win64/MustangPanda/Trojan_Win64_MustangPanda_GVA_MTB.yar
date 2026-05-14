
rule Trojan_Win64_MustangPanda_GVA_MTB{
	meta:
		description = "Trojan:Win64/MustangPanda.GVA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 54 00 4d 00 50 00 25 00 [0-3c] 2e 00 64 00 6f 00 63 00 78 00 2e 00 6c 00 6e 00 6b 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}