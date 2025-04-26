
rule Trojan_Win64_IcedID_NIC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 ff c3 48 8b c3 49 f7 e0 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 4c 2b c0 42 8a 44 85 97 41 30 02 49 ff c2 4d 63 c3 4c 3b c7 72 } //1
		$a_03_1 = {ff c1 48 8b c3 49 f7 e0 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 4c 2b c0 42 8a 44 85 f7 41 30 02 49 ff c2 4c 63 c1 4c 3b c7 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}