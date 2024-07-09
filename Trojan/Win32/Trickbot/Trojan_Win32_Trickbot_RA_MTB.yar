
rule Trojan_Win32_Trickbot_RA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 84 05 c0 f6 ff ff 40 3b c6 72 } //1
		$a_03_1 = {8a 8c 15 c0 f6 ff ff 30 08 40 83 [0-1f] 0f 90 0a 2f 00 0f b6 07 [0-0a] 99 [0-0a] f7 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}