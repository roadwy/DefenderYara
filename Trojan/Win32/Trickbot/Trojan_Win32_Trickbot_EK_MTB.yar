
rule Trojan_Win32_Trickbot_EK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c8 03 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 2b ca a1 90 01 04 0f af 05 90 01 04 03 c8 8b 15 90 01 04 0f af 15 90 01 04 03 ca a1 90 01 04 0f af 05 90 01 04 03 c8 8b 15 90 01 04 0f af 15 90 01 04 03 ca 90 00 } //1
		$a_03_1 = {69 c0 f8 00 00 00 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 69 c9 f8 00 00 00 03 d1 a1 90 01 04 0f af 05 90 01 04 69 c0 f8 00 00 00 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 69 c9 f8 00 00 00 03 d1 89 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}