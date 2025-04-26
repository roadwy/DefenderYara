
rule Trojan_Win32_Guloader_CK_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 69 66 66 65 72 65 6e 63 69 6e 67 5c 6b 72 79 62 73 6b 79 74 74 65 6e 5c 73 75 70 72 61 6d 61 78 69 6c 6c 61 72 79 } //1 differencing\krybskytten\supramaxillary
		$a_01_1 = {62 6c 67 65 73 6b 72 65 74 73 2e 62 6f 67 } //1 blgeskrets.bog
		$a_01_2 = {65 6e 65 61 6e 70 61 72 74 73 68 61 76 65 72 2e 64 65 72 } //1 eneanpartshaver.der
		$a_01_3 = {68 79 6c 64 65 62 6c 6f 6d 73 74 65 6e 2e 74 78 74 } //1 hyldeblomsten.txt
		$a_01_4 = {54 72 6f 70 68 69 5c 66 6f 72 6d 61 74 6c 6e 67 64 65 6e 73 2e 6c 6e 6b } //1 Trophi\formatlngdens.lnk
		$a_01_5 = {72 6f 63 6b 77 6f 6f 6c 65 6e 2e 62 72 61 20 } //1 rockwoolen.bra 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}