
rule Trojan_Win64_IcedID_RE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 8d 0c 8d ?? ?? ?? ?? 3a d2 74 ?? 8b 44 84 ?? 33 c1 e9 } //1
		$a_03_1 = {0f b6 8c 0c ?? ?? ?? ?? 33 c1 e9 ?? ?? ?? ?? 48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 66 3b c9 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}