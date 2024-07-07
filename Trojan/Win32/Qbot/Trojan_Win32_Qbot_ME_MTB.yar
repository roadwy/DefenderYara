
rule Trojan_Win32_Qbot_ME_MTB{
	meta:
		description = "Trojan:Win32/Qbot.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 2b d8 89 1d 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //5
		$a_00_1 = {86 c0 7c 50 b3 ca 6b 41 a5 c1 7a 65 b2 d6 08 00 c1 a5 08 56 a8 d7 7c 75 a0 c9 49 6c } //5
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5) >=10
 
}