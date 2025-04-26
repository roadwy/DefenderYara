
rule Trojan_BAT_Guloader_KAE_MTB{
	meta:
		description = "Trojan:BAT/Guloader.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 69 73 73 65 6e 74 69 65 72 69 6e 67 65 72 6e 65 73 5c 42 69 6c 61 73 73 69 73 74 65 6e 74 65 72 73 } //dissentieringernes\Bilassistenters  1
		$a_80_1 = {55 72 62 61 63 69 74 79 5c 55 6e 69 6e 73 74 61 6c 6c 5c 64 65 6c 74 72 61 6e 73 66 6f 72 6d 61 74 69 6f 6e 73 } //Urbacity\Uninstall\deltransformations  1
		$a_80_2 = {6d 61 73 6b 69 6e 66 69 6b 73 65 72 65 74 2e 69 6e 69 } //maskinfikseret.ini  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}