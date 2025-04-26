
rule Trojan_Win32_Trickbot_GK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d0 81 e2 [0-04] 79 ?? 4a 83 ca e0 42 8a 14 3a 30 14 08 40 3b c6 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}