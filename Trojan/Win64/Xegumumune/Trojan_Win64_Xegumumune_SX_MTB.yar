
rule Trojan_Win64_Xegumumune_SX_MTB{
	meta:
		description = "Trojan:Win64/Xegumumune.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_80_0 = {4b 6f 6e 67 5c 4b 65 79 6c 6f 67 67 65 72 } //Kong\Keylogger  30
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 4b 6f 6e 67 5c 43 6c 69 65 6e 74 5c 43 6c 69 65 6e 74 56 65 72 73 69 6f 6e } //Software\Kong\Client\ClientVersion  10
		$a_80_2 = {5b 4c 6f 63 61 6c 5c 43 6c 69 65 6e 74 4d 75 74 65 78 5f 25 30 38 58 } //[Local\ClientMutex_%08X  5
	condition:
		((#a_80_0  & 1)*30+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5) >=45
 
}