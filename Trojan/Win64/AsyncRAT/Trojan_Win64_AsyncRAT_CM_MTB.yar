
rule Trojan_Win64_AsyncRAT_CM_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {37 80 74 24 ?? 38 80 74 24 ?? 39 80 74 24 ?? 3a 80 74 24 ?? 3b 80 74 24 ?? 3c 80 74 24 ?? 3d 34 3e c6 44 24 ?? 31 88 44 24 ?? 48 8d 44 24 ?? 49 ff c0 42 80 3c 00 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}