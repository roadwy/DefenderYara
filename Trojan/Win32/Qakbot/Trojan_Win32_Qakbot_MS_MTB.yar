
rule Trojan_Win32_Qakbot_MS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 68 90 01 04 ff 15 90 01 04 8b 4d 90 01 01 81 c1 90 01 04 89 4d 90 01 01 8b 55 90 01 01 6b d2 90 01 01 89 55 90 01 01 a1 90 01 04 a3 90 01 04 33 c0 8b 4c 05 90 01 01 89 0d 90 01 04 89 2d 90 01 06 e8 90 01 04 68 90 01 04 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}