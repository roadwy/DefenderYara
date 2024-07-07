
rule Trojan_Win32_Qakbot_SAE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b 43 90 01 01 89 bb 90 01 04 31 04 29 83 c5 90 01 01 8b 4b 90 01 01 49 01 4b 90 01 01 8b 8b 90 01 04 01 4b 90 01 01 81 fd 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}