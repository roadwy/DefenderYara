
rule Trojan_Win32_Qakbot_PAH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 66 3b d2 90 13 bb 04 00 00 00 53 3a d2 90 13 5e f7 f6 3a c9 90 13 0f b6 44 15 90 01 01 33 c8 3a d2 90 13 8b 45 90 01 01 88 4c 05 90 01 01 90 13 8b 45 90 01 01 40 e9 90 00 } //1
		$a_01_1 = {76 69 70 73 } //1 vips
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}