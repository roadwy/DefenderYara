
rule Trojan_Win64_LucaStealer_PGLS_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 36 00 32 00 2e 00 36 00 30 00 2e 00 32 00 32 00 36 00 2e 00 39 00 37 00 3a 00 35 00 35 00 35 00 33 00 2f 00 [0-1f] 2e 00 65 00 78 00 65 00 } //5
		$a_02_1 = {68 74 00 74 00 70 3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 39 37 3a 35 35 35 33 2f [0-1f] 2e 65 78 65 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5) >=5
 
}