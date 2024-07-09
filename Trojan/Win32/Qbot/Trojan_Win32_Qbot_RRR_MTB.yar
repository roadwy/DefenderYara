
rule Trojan_Win32_Qbot_RRR_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 2c 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}