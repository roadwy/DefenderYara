
rule Trojan_Win32_Dbot_DEA_MTB{
	meta:
		description = "Trojan:Win32/Dbot.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d0 03 f0 d3 e2 89 b5 90 01 01 fd ff ff 8b f0 c1 ee 05 03 95 90 01 01 fd ff ff 03 b5 90 01 01 fd ff ff 89 55 f8 8b 85 90 01 01 fd ff ff 31 45 f8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}