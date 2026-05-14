
rule Trojan_Win64_Tedy_AHF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 83 e0 ?? 0f b6 44 10 ?? 32 04 0e 88 04 0f 48 ff c1 48 3b cb 72 } //30
		$a_01_1 = {66 0f 67 c9 66 0f 67 c9 66 0f 6e c0 0f 57 c8 66 0f 7e c8 66 89 04 0f } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}