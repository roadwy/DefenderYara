
rule Trojan_Win32_Danabot_MXZ_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d e4 8b 55 e4 3b 15 ?? ?? ?? ?? 7d 12 8b 45 e0 03 45 e4 8b 4d d8 03 4d e4 8a 11 88 10 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}