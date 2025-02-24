
rule Trojan_Win64_DBadur_GTZ_MTB{
	meta:
		description = "Trojan:Win64/DBadur.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 c8 0a 27 54 5b d2 21 54 } //5
		$a_03_1 = {2c 57 d0 87 ?? ?? ?? ?? d0 2f 95 10 32 ?? ?? 67 95 10 32 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}