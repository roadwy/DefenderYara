
rule Trojan_Win32_RenoFloss_B_dha{
	meta:
		description = "Trojan:Win32/RenoFloss.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 ff ff ff ff ?? ?? ?? ?? ?? ?? ?? 31 ?? 10 03 ?? 10 83 ?? fc 90 09 0a 00 90 90 90 90 ?? ?? ?? c9 66 b9 ?? 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}