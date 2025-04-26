
rule Trojan_Win32_Qshell_RB_MTB{
	meta:
		description = "Trojan:Win32/Qshell.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 02 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 e0 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}