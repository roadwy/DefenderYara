
rule Trojan_Win32_Trickbot_AB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c8 88 4d 90 02 08 e8 90 01 04 83 c4 90 01 01 0f b6 55 90 01 01 0f b6 45 90 01 01 33 c2 88 45 90 02 08 e8 90 01 04 83 c4 90 01 01 8a 4d 90 01 01 80 c1 90 01 01 88 4d 90 01 01 68 90 01 04 e8 90 01 04 83 c4 90 01 01 8b 55 90 01 01 8a 45 90 01 01 88 02 90 0a 70 00 0f b6 45 90 01 01 0f b6 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}