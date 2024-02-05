
rule Trojan_Win32_Emotet_RWB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  01 00 
		$a_80_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllUnregisterServer  01 00 
		$a_80_2 = {66 69 73 63 61 6c 6c 79 } //fiscally  01 00 
		$a_80_3 = {61 70 6f 6e 65 75 72 6f 73 69 73 } //aponeurosis  01 00 
		$a_80_4 = {64 65 6c 70 68 69 6e 69 63 } //delphinic  01 00 
		$a_80_5 = {70 61 6d 70 61 6e 67 61 6e } //pampangan  01 00 
		$a_80_6 = {70 65 72 6a 75 72 65 64 } //perjured  01 00 
		$a_80_7 = {73 65 64 69 6d 65 6e 74 61 74 65 } //sedimentate  01 00 
		$a_80_8 = {73 70 69 6e 73 74 65 72 69 73 6d } //spinsterism  00 00 
	condition:
		any of ($a_*)
 
}