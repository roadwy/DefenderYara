
rule Trojan_Win64_IcedID_VN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c8 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 36 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 9c ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 85 84 0b } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}