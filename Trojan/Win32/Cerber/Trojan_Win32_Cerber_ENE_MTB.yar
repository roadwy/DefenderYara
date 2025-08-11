
rule Trojan_Win32_Cerber_ENE_MTB{
	meta:
		description = "Trojan:Win32/Cerber.ENE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 5c 91 40 00 dc 32 cb 01 00 c0 42 00 f8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}