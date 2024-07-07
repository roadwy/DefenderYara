
rule Trojan_Win64_StrelaStealer_GPAE_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 09 d9 09 fd 41 31 e9 44 89 cf 83 f7 ff 81 f7 ff ff ff ff 83 e7 ff 44 89 d3 81 f3 ff ff ff ff 81 e3 ff ff ff ff 44 89 d5 81 f5 ff ff ff ff 81 e5 ff ff ff ff 09 eb 83 f3 ff 44 89 d5 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}