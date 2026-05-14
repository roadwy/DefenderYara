
rule Trojan_Win64_TransferLoader_CM_MTB{
	meta:
		description = "Trojan:Win64/TransferLoader.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 03 48 8b 54 24 ?? 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 4c 24 ?? 88 84 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}