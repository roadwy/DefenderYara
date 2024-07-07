
rule Trojan_Win32_Qakbot_VIS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.VIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 44 15 a8 33 c8 3a d2 74 00 8b 45 f4 88 4c 05 ac e9 8a 00 00 00 e9 79 ff ff ff } //1
		$a_01_1 = {58 35 35 35 } //1 X555
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}