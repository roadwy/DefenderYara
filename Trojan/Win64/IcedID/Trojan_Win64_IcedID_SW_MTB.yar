
rule Trojan_Win64_IcedID_SW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 66 3b db 74 ?? 8b c2 89 44 24 ?? 3a db 74 ?? 8b 4c 24 ?? 03 c8 3a ff 74 } //1
		$a_03_1 = {8b c2 89 44 24 ?? 3a db 74 ?? 0f b6 8c 0c ?? ?? ?? ?? 33 c1 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}