
rule Trojan_Win32_Danabot_AC_MTB{
	meta:
		description = "Trojan:Win32/Danabot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 57 c0 c1 e1 90 01 01 03 ca 66 0f 13 05 90 02 20 33 c8 81 3d 90 02 30 89 4c 24 10 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}