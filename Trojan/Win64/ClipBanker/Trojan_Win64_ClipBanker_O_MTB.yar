
rule Trojan_Win64_ClipBanker_O_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 00 5e d0 b2 e8 f0 cd ce ff 90 e8 6a 2e ef ff 48 89 44 24 40 48 89 5c 24 28 e8 fb 6e ff ff 48 89 c1 48 89 df 48 8b 44 24 40 48 8b 5c 24 28 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}