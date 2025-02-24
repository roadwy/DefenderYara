
rule Trojan_Win64_IcedId_HZ_MTB{
	meta:
		description = "Trojan:Win64/IcedId.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c0 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 48 ff cf } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}