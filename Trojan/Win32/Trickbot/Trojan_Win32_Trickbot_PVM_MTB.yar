
rule Trojan_Win32_Trickbot_PVM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PVM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 5e 3e 03 c2 80 e2 80 32 d3 8a 18 32 da 88 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}