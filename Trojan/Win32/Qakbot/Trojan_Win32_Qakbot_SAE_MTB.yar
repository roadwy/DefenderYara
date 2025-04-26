
rule Trojan_Win32_Qakbot_SAE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b 43 ?? 89 bb ?? ?? ?? ?? 31 04 29 83 c5 ?? 8b 4b ?? 49 01 4b ?? 8b 8b ?? ?? ?? ?? 01 4b ?? 81 fd ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}