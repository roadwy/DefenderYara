
rule Trojan_Win64_IcedId_PAI_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 98 48 8b 4c 24 ?? 0f b6 04 01 48 63 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 33 c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9 [0-04] 48 83 [0-02] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}