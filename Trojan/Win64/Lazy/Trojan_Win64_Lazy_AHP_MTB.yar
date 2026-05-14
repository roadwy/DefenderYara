
rule Trojan_Win64_Lazy_AHP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e 40 ?? 41 0f 54 d3 66 0f 67 d2 66 0f 67 d2 66 41 0f fc d5 0f 57 d0 66 0f 7e 50 } //30
		$a_01_1 = {72 61 6e 64 6f 6d 73 68 69 74 69 64 66 6b 72 61 68 31 32 34 34 36 36 32 } //20 randomshitidfkrah1244662
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}