
rule Trojan_Win64_Lazy_AHB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 31 c6 45 88 74 35 00 0f be 44 35 00 48 ff c6 8b 15 ?? ?? ?? ?? 0f af c2 01 c7 eb } //30
		$a_03_1 = {44 31 e8 42 88 44 35 00 8b 15 ?? ?? ?? ?? 0f be c0 49 ff c6 0f af c2 01 c6 eb } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}