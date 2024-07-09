
rule Trojan_Win32_Danabot_GXQ_MTB{
	meta:
		description = "Trojan:Win32/Danabot.GXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? 4b 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}