
rule Trojan_Win64_Lazy_AHQ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 83 c0 ?? 8b 8c 24 c4 01 00 00 33 c8 8b c1 48 63 8c 24 80 00 00 00 88 84 0c 06 02 00 00 eb } //30
		$a_01_1 = {ff c8 0f b6 4c 24 50 2b c1 89 84 24 e8 00 00 00 0f b6 44 24 50 44 8b 8c 24 e8 00 00 00 4c 8b 84 24 c0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}