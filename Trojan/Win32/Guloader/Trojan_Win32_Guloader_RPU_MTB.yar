
rule Trojan_Win32_Guloader_RPU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 61 6b 74 69 6f 6e 73 67 72 75 70 70 65 72 6e 65 73 } //1 Software\aktionsgruppernes
		$a_01_1 = {62 6f 72 67 65 72 6c 69 67 73 74 65 73 5c 46 65 6c 69 6e 6f 70 68 69 6c 65 } //1 borgerligstes\Felinophile
		$a_01_2 = {4b 49 4c 4c 49 4e 47 45 54 55 4e 47 45 52 4e 45 53 5c 41 74 68 65 6e 61 65 75 6d 73 2e 6f 70 73 } //1 KILLINGETUNGERNES\Athenaeums.ops
		$a_01_3 = {42 69 6c 6d 6f 64 65 6c 5c 73 75 70 65 72 70 61 72 74 69 65 6e 74 5c 43 61 6e 64 69 64 65 } //1 Bilmodel\superpartient\Candide
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 53 74 79 6d 70 68 61 6c 75 73 39 38 } //1 Software\Stymphalus98
		$a_01_5 = {56 65 73 74 6c 69 67 65 73 5c 50 72 65 61 64 6f 6c 65 73 63 65 6e 74 32 34 34 } //1 Vestliges\Preadolescent244
		$a_01_6 = {70 68 6f 63 6f 65 6e 61 } //1 phocoena
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Guloader_RPU_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 5d 00 3d bb 00 00 00 83 fe 2d } //1
		$a_01_1 = {81 fa e9 00 00 00 81 f9 a2 00 00 00 01 1c 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}