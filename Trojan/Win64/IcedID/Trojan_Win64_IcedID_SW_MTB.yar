
rule Trojan_Win64_IcedID_SW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 66 3b db 74 90 01 01 8b c2 89 44 24 90 01 01 3a db 74 90 01 01 8b 4c 24 90 01 01 03 c8 3a ff 74 90 00 } //1
		$a_03_1 = {8b c2 89 44 24 90 01 01 3a db 74 90 01 01 0f b6 8c 0c 90 01 04 33 c1 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}