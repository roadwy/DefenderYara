
rule Trojan_Win32_Qakbot_E{
	meta:
		description = "Trojan:Win32/Qakbot.E,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 6d 74 6e 5c 70 6c 64 72 73 73 2e 70 64 62 } //1 emtn\pldrss.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}