
rule Trojan_Win32_Qbot_DSA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ff 8b 15 90 01 04 a1 90 01 04 89 02 5f 5d c3 90 09 27 00 a1 90 01 04 a3 90 01 06 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}