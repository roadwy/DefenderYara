
rule Trojan_Win32_AgentTesla_SH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 a8 21 a7 3e [0-06] eb [0-91] 81 c1 99 1f 9a 02 [0-15] eb [0-20] 8b 17 [0-10] 39 ca 75 } //1
		$a_03_1 = {89 0c 18 eb 90 0a 00 20 4b [0-70] 4b [0-40] 4b [0-40] 4b [0-70] 8b 0c 1f [0-50] 31 f1 [0-70] 89 0c 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}