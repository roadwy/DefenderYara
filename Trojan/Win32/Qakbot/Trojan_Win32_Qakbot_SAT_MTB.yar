
rule Trojan_Win32_Qakbot_SAT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 10 a1 5c ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 83 c0 ?? a3 ?? ?? ?? ?? 33 c0 a3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}