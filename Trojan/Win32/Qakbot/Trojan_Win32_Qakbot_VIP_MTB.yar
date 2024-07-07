
rule Trojan_Win32_Qakbot_VIP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.VIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 03 45 ec 03 d8 e8 90 01 04 2b d8 a1 90 01 04 89 18 e8 90 00 } //1
		$a_03_1 = {8b 45 d8 03 45 ac 03 45 ec 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}