
rule Trojan_Win32_Zbot_PABU_MTB{
	meta:
		description = "Trojan:Win32/Zbot.PABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0e 03 cb b8 00 40 00 00 c1 c0 14 03 f0 c1 c1 08 89 4d 94 03 d5 52 e8 90 01 04 56 59 5a 2b d5 8b 45 a8 85 c7 c1 c0 16 03 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}