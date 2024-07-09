
rule Trojan_Win64_IcedID_RHZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 41 ff c3 49 f7 e0 48 c1 ea 02 48 6b c2 ?? 4c 2b c0 42 8a 44 84 20 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72 } //1
		$a_03_1 = {48 8b c3 ff c1 49 f7 e0 48 c1 ea 02 48 6b c2 ?? 4c 2b c0 42 8a 44 84 58 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}