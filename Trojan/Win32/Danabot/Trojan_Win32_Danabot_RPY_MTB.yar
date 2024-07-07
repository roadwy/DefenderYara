
rule Trojan_Win32_Danabot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Danabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 2e 64 6c 66 c7 05 90 01 04 6c 00 c7 05 90 01 04 6b 65 72 6e 66 c7 05 90 01 04 65 6c c6 05 90 01 04 33 ff 15 90 00 } //1
		$a_02_1 = {6c 50 72 6f c7 05 90 01 04 65 63 74 00 88 0d 90 01 04 c7 05 90 01 04 72 74 75 61 66 c7 05 90 01 04 56 69 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}