
rule Trojan_Win32_Convagent_DD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 3a 00 74 f8 90 ac 32 02 aa 42 e2 f3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}