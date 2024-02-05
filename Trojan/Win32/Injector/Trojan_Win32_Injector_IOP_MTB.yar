
rule Trojan_Win32_Injector_IOP_MTB{
	meta:
		description = "Trojan:Win32/Injector.IOP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 09 21 12 1d 38 39 17 2d 1c 0c 19 09 38 1e 09 30 02 0c 38 } //00 00 
	condition:
		any of ($a_*)
 
}