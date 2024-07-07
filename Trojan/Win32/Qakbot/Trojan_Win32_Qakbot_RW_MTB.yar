
rule Trojan_Win32_Qakbot_RW_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d f2 05 00 00 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}