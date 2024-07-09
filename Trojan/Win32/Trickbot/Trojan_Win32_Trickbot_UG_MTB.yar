
rule Trojan_Win32_Trickbot_UG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.UG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b ce e8 [0-04] 8b ?? ?? ?? 8b f8 8b ?? 83 e0 ?? 50 e8 [0-04] 8a ?? 30 ?? 8b ?? ?? 2b ?? ?? 43 3b ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}