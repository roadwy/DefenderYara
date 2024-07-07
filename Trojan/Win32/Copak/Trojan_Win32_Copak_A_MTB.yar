
rule Trojan_Win32_Copak_A_MTB{
	meta:
		description = "Trojan:Win32/Copak.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 1a 42 21 f6 39 ca 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}