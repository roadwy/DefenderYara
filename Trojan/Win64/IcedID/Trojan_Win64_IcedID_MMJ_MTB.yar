
rule Trojan_Win64_IcedID_MMJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 00 8b 85 90 01 04 89 c2 c1 fa 90 01 01 c1 ea 90 01 01 01 d0 83 e0 90 01 01 29 d0 48 98 48 03 85 90 01 04 0f b6 00 44 31 c0 88 01 83 85 90 01 05 8b 95 90 01 04 8b 85 90 01 04 39 c2 0f 92 c0 84 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}