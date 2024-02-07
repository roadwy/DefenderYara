
rule Trojan_Win32_VB_BD{
	meta:
		description = "Trojan:Win32/VB.BD,SIGNATURE_TYPE_PEHSTR,1f 00 1e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 46 00 6c 00 6f 00 72 00 69 00 6e 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 45 00 76 00 6f 00 6c 00 6f 00 75 00 74 00 69 00 6f 00 6e 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //0a 00  \AC:\Documents and Settings\Florin\Desktop\Evoloution\Server\Server.vbp
		$a_01_1 = {7b 00 45 00 6e 00 74 00 65 00 72 00 7d 00 00 00 08 00 00 00 7b 00 42 00 53 00 7d 00 } //01 00 
		$a_01_2 = {67 68 6a 69 74 61 } //01 00  ghjita
		$a_01_3 = {6d 75 68 61 68 61 } //0a 00  muhaha
		$a_01_4 = {4d 53 57 69 6e 73 6f 63 6b 4c 69 62 } //00 00  MSWinsockLib
	condition:
		any of ($a_*)
 
}