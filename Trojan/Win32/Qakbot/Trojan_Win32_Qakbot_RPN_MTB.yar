
rule Trojan_Win32_Qakbot_RPN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0 } //1
		$a_01_1 = {33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}