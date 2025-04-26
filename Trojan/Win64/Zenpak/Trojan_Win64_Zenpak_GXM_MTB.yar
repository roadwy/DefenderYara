
rule Trojan_Win64_Zenpak_GXM_MTB{
	meta:
		description = "Trojan:Win64/Zenpak.GXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b ca 42 8a 04 11 41 30 01 49 ff c1 41 81 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}