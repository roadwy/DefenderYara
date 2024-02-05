
rule Trojan_Win32_Injector_RAQ_MTB{
	meta:
		description = "Trojan:Win32/Injector.RAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f4 01 00 00 75 05 90 02 20 c3 90 09 80 00 90 02 20 e8 90 01 01 00 00 00 90 02 20 31 90 02 20 39 90 01 01 90 03 01 01 7c 75 90 02 20 c3 90 02 20 8d 90 02 20 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}