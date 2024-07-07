
rule Trojan_Win32_Qbot_RPM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 89 5d a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}