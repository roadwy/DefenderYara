
rule Trojan_Win32_Qakbot_PK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ?? 33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}