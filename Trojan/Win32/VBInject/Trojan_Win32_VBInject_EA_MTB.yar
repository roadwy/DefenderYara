
rule Trojan_Win32_VBInject_EA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.EA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 f0 83 c6 01 31 f0 3b 84 24 18 01 00 00 75 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}