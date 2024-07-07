
rule Trojan_Win32_Qakbot_RGQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 c7 05 90 01 04 f4 6e e0 f7 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 2b 45 90 01 01 89 45 90 01 01 81 3d 90 01 04 d9 02 00 00 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}