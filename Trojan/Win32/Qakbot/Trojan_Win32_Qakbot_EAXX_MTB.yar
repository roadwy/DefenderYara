
rule Trojan_Win32_Qakbot_EAXX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EAXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}