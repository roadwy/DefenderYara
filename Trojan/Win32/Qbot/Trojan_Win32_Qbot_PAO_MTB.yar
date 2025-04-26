
rule Trojan_Win32_Qbot_PAO_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 45 a4 8b 45 ?? 8b 55 ?? 01 02 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 8b 45 ?? 33 10 89 55 ?? 8b 45 ?? 8b 55 ?? 89 02 8b 45 a8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}