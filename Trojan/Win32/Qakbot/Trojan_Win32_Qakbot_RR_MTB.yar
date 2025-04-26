
rule Trojan_Win32_Qakbot_RR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 1f 8a c5 83 5f 04 00 83 ef 08 f6 e9 02 c3 f6 ed 8a c8 02 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}