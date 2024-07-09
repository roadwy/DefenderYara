
rule Trojan_Win64_IcedID_DL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 b9 ?? ?? ?? ?? 48 6b c9 ?? 0f be 8c 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}