
rule Trojan_Win64_IcedId_PY_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ce 48 8d 15 90 01 04 8a 0a 88 4c 90 01 02 80 44 90 02 04 c0 64 90 02 04 8a 4c 90 02 02 88 4c 90 02 02 8a 4a 01 88 4c 90 02 02 80 44 90 02 04 8a 4c 90 02 02 08 4c 90 02 02 8a 4c 90 02 02 30 4c 90 02 02 fe 44 90 02 02 8a 4c 90 02 02 88 0c 38 39 fe 74 90 02 02 48 ff c7 48 83 c2 90 02 02 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}