
rule Trojan_Win32_Qbot_DSE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 05 c2 5a 00 00 8b 4d 90 01 01 8b 11 2b d0 8b 45 90 01 01 89 10 90 09 0a 00 8b 45 90 01 01 89 10 68 90 00 } //1
		$a_02_1 = {8b d8 33 d9 8b ff c7 05 90 01 04 00 00 00 00 01 1d 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 5f 5b 5d c3 90 09 05 00 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}