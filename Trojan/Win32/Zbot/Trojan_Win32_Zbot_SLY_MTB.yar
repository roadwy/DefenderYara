
rule Trojan_Win32_Zbot_SLY_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 04 50 33 db 53 53 68 28 82 41 00 68 02 00 00 80 ff 15 0c 80 41 00 3b c3 74 06 83 f8 02 0f 95 c3 8a c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}