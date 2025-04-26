
rule Trojan_Win64_IcedID_TYA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 ff c3 48 8b c3 49 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 4c 2b c8 42 8a 44 8c ?? 41 30 02 49 ff c2 4d 63 cb 4c 3b cf 72 } //1
		$a_03_1 = {ff c1 48 8b c3 49 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 4c 2b c8 42 8a 44 8c ?? 41 30 02 49 ff c2 4c 63 c9 4c 3b cf 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}