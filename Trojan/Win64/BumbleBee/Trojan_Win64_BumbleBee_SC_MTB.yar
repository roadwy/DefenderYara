
rule Trojan_Win64_BumbleBee_SC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 43 08 48 81 f1 ?? ?? ?? ?? 48 89 48 ?? 48 8b 43 ?? 4c ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 8b 8b ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d } //1
		$a_03_1 = {44 8b 04 88 48 ?? ?? ?? ?? ?? ?? 44 03 ce 48 ?? ?? ?? ?? ?? ?? 44 01 04 88 44 3b 8b ?? ?? ?? ?? 0f 8c } //1
		$a_00_2 = {48 51 4c 51 79 41 4f 54 66 7a } //1 HQLQyAOTfz
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}