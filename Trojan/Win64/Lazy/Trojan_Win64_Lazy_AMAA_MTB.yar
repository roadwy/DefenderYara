
rule Trojan_Win64_Lazy_AMAA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0b 49 8d 14 18 48 83 fa 64 73 ?? 0f b6 c1 80 e9 ?? 34 ?? 0f b6 c9 f6 c2 ?? 0f b6 c0 0f 45 c8 49 8b c1 48 8b d3 88 0c 03 48 ff c3 49 8d 04 18 49 3b c2 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}