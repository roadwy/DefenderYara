
rule Trojan_Win32_Qakbot_GU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d [0-0f] 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}