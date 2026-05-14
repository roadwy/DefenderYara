
rule Trojan_Win64_Convagent_SXG_MTB{
	meta:
		description = "Trojan:Win64/Convagent.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 8c 08 ?? ?? ?? ?? f3 0f 6f 84 05 ?? ?? ?? ?? 0f 57 c8 f3 0f 7f 8c 05 ?? ?? ?? ?? 48 83 c0 10 48 83 f8 20 7c d8 } //20
		$a_03_1 = {48 89 45 00 48 8b 45 00 48 89 45 ?? 48 8b 84 11 ?? ?? ?? ?? 48 31 44 0d ?? 48 83 c1 08 48 83 f9 10 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}