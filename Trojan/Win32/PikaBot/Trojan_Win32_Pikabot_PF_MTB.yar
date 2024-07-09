
rule Trojan_Win32_Pikabot_PF_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 54 15 ?? 33 ca b8 01 00 00 00 6b d0 00 0f be 84 15 [0-04] 69 d0 [0-04] 8b 45 ?? 2b c2 8b 55 ?? 88 0c 02 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}