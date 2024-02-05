
rule Trojan_Win32_Injector_DD_MTB{
	meta:
		description = "Trojan:Win32/Injector.DD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {87 5c 7f 17 f7 e6 87 35 7f 2a f7 01 87 24 7f 40 f7 a8 87 86 7f 59 f7 78 87 19 7f 37 f7 8d 87 69 7f af f7 a0 87 fb } //00 00 
	condition:
		any of ($a_*)
 
}