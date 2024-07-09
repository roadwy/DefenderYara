
rule Trojan_Win32_Qakbot_PG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 2c 03 45 [0-30] 89 ?? b0 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 8b 45 ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}