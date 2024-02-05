
rule Trojan_Win32_Injector_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 50 46 30 06 54 46 6f 72 6d 33 05 46 6f 72 6d 33 04 4c 65 66 74 03 c0 00 03 54 6f 70 02 7c 05 57 69 64 74 68 03 88 04 06 48 65 69 67 68 74 03 58 02 07 43 61 70 74 69 6f 6e 06 05 46 6f 72 6d 33 05 43 6f 6c 6f 72 07 09 63 6c 42 74 6e 46 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}