
rule Trojan_Win32_Qakbot_SJP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 30 8b 40 0c 66 3b c9 74 ?? 8b 40 ?? 8b 4d ?? eb ?? 83 ec ?? bb ?? ?? ?? ?? 66 3b c0 74 ?? 3b 48 ?? 72 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}