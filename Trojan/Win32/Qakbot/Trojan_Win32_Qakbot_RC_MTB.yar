
rule Trojan_Win32_Qakbot_RC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 8b 45 ec 66 3b e4 74 0b 03 45 f0 0f b6 08 66 3b f6 74 e1 03 45 f0 88 08 e9 3f 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}