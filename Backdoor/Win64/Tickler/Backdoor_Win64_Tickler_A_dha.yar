
rule Backdoor_Win64_Tickler_A_dha{
	meta:
		description = "Backdoor:Win64/Tickler.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e9 71 0b 00 00 c6 84 24 ?? ?? ?? ?? ?? b0 ?? b1 ?? b2 ?? 41 b0 ?? 41 b1 ?? 41 b2 ?? 45 33 db 34 ?? 88 84 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}