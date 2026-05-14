
rule Trojan_Win64_DLLHijack_DL_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 83 e0 0f 42 0f b6 0c 08 48 8d 44 24 [0-04] 48 83 7d 88 10 48 0f 43 44 24 [0-04] f6 d1 30 0c 10 48 ff c2 49 3b d0 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}