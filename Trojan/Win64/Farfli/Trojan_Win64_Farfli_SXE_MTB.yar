
rule Trojan_Win64_Farfli_SXE_MTB{
	meta:
		description = "Trojan:Win64/Farfli.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 04 11 49 ff c1 33 01 c1 c0 05 05 ?? ?? ?? ?? 89 01 4d 3b c8 72 e7 } //20
		$a_03_1 = {0f b6 0c 02 41 33 0a 8b c1 c1 e9 0d 69 c0 ?? ?? ?? ?? 33 c1 41 89 02 c1 e8 10 43 32 44 19 ?? 41 32 02 43 88 44 19 ?? 4d 3b c8 72 c4 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}