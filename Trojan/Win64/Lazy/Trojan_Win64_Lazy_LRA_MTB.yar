
rule Trojan_Win64_Lazy_LRA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 06 48 8d 55 67 48 8b ce 4c 89 75 77 4c 89 75 67 ff ?? ?? 48 8b 5d 67 48 85 db 0f ?? ?? ?? ?? ?? 48 8b 4d 77 48 85 c9 74 ?? 48 8b 01 } //20
		$a_03_1 = {48 8b 4d b7 48 8b 01 ff ?? ?? 48 8b 75 b7 4c 8d 45 c7 b9 11 00 00 00 4c 89 75 6f 41 8b d7 4c 89 75 7f } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}