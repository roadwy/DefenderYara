
rule Trojan_Win32_Qakbot_DHE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {4c 61 66 6f 73 6f 70 69 6a 69 62 } //1 Lafosopijib
		$a_81_1 = {63 6f 7a 6f 63 61 79 69 78 61 74 75 } //1 cozocayixatu
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}