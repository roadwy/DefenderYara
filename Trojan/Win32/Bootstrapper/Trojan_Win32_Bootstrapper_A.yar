
rule Trojan_Win32_Bootstrapper_A{
	meta:
		description = "Trojan:Win32/Bootstrapper.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb c1 e1 04 03 4d d8 8d 14 18 33 ca 33 4d f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}