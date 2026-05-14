
rule Trojan_Win64_Lazy_SJ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 44 0f b6 d2 42 8a 84 14 f0 0a 00 00 41 00 c0 45 0f b6 c8 42 8a 94 0c f0 0a 00 00 42 88 94 14 f0 0a 00 00 42 88 84 0c f0 0a 00 00 42 02 84 14 f0 0a 00 00 0f b6 c0 8a 84 04 f0 0a 00 00 30 04 0e 48 ff c1 b0 c3 49 89 cb e9 bd fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}