
rule Trojan_Win32_Lokibot_TW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.TW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 05 10 01 90 8b c2 03 c3 90 05 10 01 90 c6 00 90 01 01 90 05 10 01 90 43 81 fb 90 01 04 75 90 00 } //1
		$a_03_1 = {83 c4 10 5f 5e c3 8d 40 00 90 90 90 05 10 01 90 80 f2 90 01 01 88 10 90 90 90 05 10 01 90 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}