
rule Trojan_Win64_Tedy_SXA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 f3 0f 7f 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 41 b9 02 00 00 00 41 b0 ff 33 d2 ff 15 } //20
		$a_03_1 = {48 89 45 00 48 8b 45 00 48 89 45 ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 00 48 8b 45 00 48 89 45 ?? 4c 89 65 00 48 8b 45 00 48 89 45 ?? 48 8d 45 ?? c5 fe 6f 45 ?? c5 fd ef 4d ?? c5 fd 7f 4d } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}