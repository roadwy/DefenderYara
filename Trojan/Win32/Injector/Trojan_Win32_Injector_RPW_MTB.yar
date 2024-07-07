
rule Trojan_Win32_Injector_RPW_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c2 02 00 00 00 90 02 10 39 ca 7e 90 09 30 00 90 02 20 8a 1a 90 02 10 88 1e 90 02 10 46 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injector_RPW_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d c4 00 00 00 83 fb 1a 31 db 83 f8 00 83 fa 0d 33 1c 0e 83 fa 57 83 fb 5d 09 1c 08 81 fb a3 00 00 00 81 f9 fa 00 00 00 31 3c 08 83 f8 11 81 fb 9b 00 00 00 81 e9 42 02 00 00 83 f9 21 83 f9 1b 81 c1 3d 02 00 00 90 83 f9 1a 41 7d b3 83 f8 02 81 fa d5 00 00 00 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injector_RPW_MTB_3{
	meta:
		description = "Trojan:Win32/Injector.RPW!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {54 65 63 6e 6f 6c 6f 67 67 61 6e 64 6f } //1 Tecnologgando
		$a_01_1 = {42 65 74 74 79 } //1 Betty
		$a_01_2 = {54 72 75 6d 70 61 } //1 Trumpa
		$a_01_3 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {44 65 43 72 69 74 74 61 } //1 DeCritta
		$a_01_6 = {53 74 61 6d 70 61 } //1 Stampa
		$a_01_7 = {49 6e 73 74 61 6c 6c 61 6d 69 } //1 Installami
		$a_01_8 = {40 00 ff d0 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}