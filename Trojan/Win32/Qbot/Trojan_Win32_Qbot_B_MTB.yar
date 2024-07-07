
rule Trojan_Win32_Qbot_B_MTB{
	meta:
		description = "Trojan:Win32/Qbot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 08 5f 5d c3 90 0a 40 00 a1 90 01 04 a3 90 01 06 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 8b ff a1 90 00 } //2
		$a_03_1 = {89 08 5f 5b 5d c3 90 0a 40 00 8b ff c7 05 90 01 08 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 0a 00 02 a1 90 01 04 31 0d 90 01 04 a1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}