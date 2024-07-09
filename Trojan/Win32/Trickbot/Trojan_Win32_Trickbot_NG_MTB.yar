
rule Trojan_Win32_Trickbot_NG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e6 c1 ea ?? 8b c2 c1 e0 ?? 03 c2 03 c0 8b de 2b d8 8b 44 24 ?? 03 fe 3b [0-1d] 8a 0c 18 30 0f 8b 45 ?? 2b 45 ?? 46 3b f0 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}