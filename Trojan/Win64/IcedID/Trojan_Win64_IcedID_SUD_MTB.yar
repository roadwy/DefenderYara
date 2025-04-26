
rule Trojan_Win64_IcedID_SUD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 41 ff c3 49 f7 e1 48 c1 ea 04 48 6b c2 ?? 4c 2b c8 42 8a 44 8d b7 41 30 02 49 ff c2 4d 63 cb 4c 3b cf 72 } //1
		$a_03_1 = {48 8b c3 ff c1 49 f7 e1 48 c1 ea 04 48 6b c2 ?? 4c 2b c8 42 8a 44 8d 07 41 30 02 49 ff c2 4c 63 c9 4c 3b cf 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}