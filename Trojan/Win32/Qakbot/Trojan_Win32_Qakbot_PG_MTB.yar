
rule Trojan_Win32_Qakbot_PG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 2c 03 45 90 02 30 89 90 01 01 b0 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 8b 45 90 01 01 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}