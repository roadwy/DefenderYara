
rule Trojan_Win32_KryptInject_PDSK_MTB{
	meta:
		description = "Trojan:Win32/KryptInject.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8f 45 f8 31 4d f8 8b 55 f8 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}