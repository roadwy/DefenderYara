
rule Trojan_Win64_ClipBanker_S_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 5c 24 48 48 8b 4c 24 50 48 c7 44 24 48 00 00 00 00 44 0f 11 7c 24 50 31 c0 e8 6b f1 f6 ff e8 06 87 fc ff 48 89 44 24 40 48 89 5c 24 28 48 8b 4c 24 20 48 39 cb 75 27 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}