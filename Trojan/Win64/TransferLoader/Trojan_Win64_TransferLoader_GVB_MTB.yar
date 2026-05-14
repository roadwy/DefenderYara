
rule Trojan_Win64_TransferLoader_GVB_MTB{
	meta:
		description = "Trojan:Win64/TransferLoader.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 63 44 24 ?? 48 83 f8 ?? 73 2f 48 63 44 24 24 0f b6 44 04 ?? 8b 4c 24 ?? c1 e1 03 48 8b 54 24 ?? 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 4c 24 24 88 84 0c ?? ?? ?? ?? eb a8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}