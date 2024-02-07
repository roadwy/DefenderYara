
rule Ransom_MSIL_WannaCrypt_PD_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 46 00 72 00 6f 00 6d 00 20 00 4d 00 61 00 69 00 6e 00 2e 00 2e 00 2e 00 49 00 20 00 44 00 6f 00 6e 00 27 00 74 00 20 00 44 00 6f 00 20 00 41 00 6e 00 79 00 74 00 68 00 69 00 6e 00 67 00 } //01 00  Hello From Main...I Don't Do Anything
		$a_01_1 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 54 00 68 00 65 00 72 00 65 00 20 00 46 00 72 00 6f 00 6d 00 20 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //01 00  Hello There From Uninstall
		$a_01_2 = {49 00 20 00 73 00 68 00 6f 00 75 00 6c 00 64 00 6e 00 27 00 74 00 20 00 72 00 65 00 61 00 6c 00 6c 00 79 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 } //01 00  I shouldn't really execute
		$a_01_3 = {24 30 35 34 37 66 66 34 30 2d 35 32 35 35 2d 34 32 61 32 2d 62 65 62 37 2d 32 66 66 30 64 62 66 37 64 33 62 61 } //01 00  $0547ff40-5255-42a2-beb7-2ff0dbf7d3ba
		$a_01_4 = {5c 41 6c 6c 54 68 65 54 68 69 6e 67 73 2e 64 6c 6c } //00 00  \AllTheThings.dll
	condition:
		any of ($a_*)
 
}