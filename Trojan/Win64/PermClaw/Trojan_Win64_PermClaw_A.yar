
rule Trojan_Win64_PermClaw_A{
	meta:
		description = "Trojan:Win64/PermClaw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 48 8b ?? 24 ?? 0f be ?? ?? 0f b6 ?? ?? 33 c1 } //1
		$a_03_1 = {48 89 48 30 b8 4d 4f 00 00 48 8b ?? 24 38 66 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}