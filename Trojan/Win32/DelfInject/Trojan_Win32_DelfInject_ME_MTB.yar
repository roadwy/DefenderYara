
rule Trojan_Win32_DelfInject_ME_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.ME!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 0b 00 00 00 d2 e1 f6 ed ef ee e4 ae } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}