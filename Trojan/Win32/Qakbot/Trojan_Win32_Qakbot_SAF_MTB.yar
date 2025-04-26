
rule Trojan_Win32_Qakbot_SAF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 46 ?? 89 9e ?? ?? ?? ?? 31 04 29 83 c5 ?? 8b 46 ?? 48 01 46 ?? 8b 46 ?? 01 46 ?? 81 fd ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}