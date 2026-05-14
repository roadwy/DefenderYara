
rule Trojan_Win64_Rozena_AH_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 11 01 48 b8 2e 00 64 00 6c 00 6c 00 48 89 41 ?? 66 83 61 18 ?? 48 8d 54 24 24 83 22 ?? ff 15 } //20
		$a_03_1 = {48 89 f7 f3 aa 48 b8 50 00 41 00 54 00 48 00 48 8d 4c 24 26 48 89 01 66 83 61 08 ?? 48 89 f2 41 b8 ?? ?? 00 00 ff 15 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}