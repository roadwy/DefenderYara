
rule Trojan_Win64_IcedID_MMJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 89 c2 c1 fa ?? c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 48 03 85 ?? ?? ?? ?? 0f b6 00 44 31 c0 88 01 83 85 ?? ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 39 c2 0f 92 c0 84 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}