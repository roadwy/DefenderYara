
rule Trojan_Win32_Qakbot_RK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a8 03 45 ac 48 89 45 a4 } //1
		$a_01_1 = {8b 55 d8 8b 12 03 55 a8 03 c2 8b 55 d8 89 02 } //1
		$a_01_2 = {03 d8 8b 45 d8 33 18 89 5d a0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}