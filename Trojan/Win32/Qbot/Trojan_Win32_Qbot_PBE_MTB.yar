
rule Trojan_Win32_Qbot_PBE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 05 90 01 01 3a c9 90 13 8b 45 90 01 01 33 d2 3a f6 90 13 bb 04 00 00 00 53 3a ff 90 13 5e f7 f6 3a c9 90 13 0f b6 44 15 90 01 01 33 c8 66 3b ed 90 13 8b 45 90 01 01 88 4c 05 ac 90 13 8b 45 f4 40 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}