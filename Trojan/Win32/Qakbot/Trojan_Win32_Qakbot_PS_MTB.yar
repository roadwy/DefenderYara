
rule Trojan_Win32_Qakbot_PS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 14 31 8b 0d 90 02 04 33 15 90 02 04 89 14 0e 83 c6 04 8b 0d 90 02 04 81 c1 90 02 04 0f af 48 90 01 01 89 48 90 01 01 8b 0d 90 02 06 88 90 02 04 8b 0d 90 02 04 8b 49 90 02 04 2b 0d 90 02 04 83 e9 90 02 04 0f af 88 90 02 04 89 88 90 02 04 8b 0d 90 02 04 81 f1 90 02 04 29 88 90 02 04 81 fe 90 02 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}