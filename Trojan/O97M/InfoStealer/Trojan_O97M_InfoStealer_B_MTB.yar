
rule Trojan_O97M_InfoStealer_B_MTB{
	meta:
		description = "Trojan:O97M/InfoStealer.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 75 70 6c 6f 61 64 22 20 2b 20 76 62 43 72 4c 66 20 2b 20 76 62 43 72 4c 66 } //1 "Content-Type: application/upload" + vbCrLf + vbCrLf
		$a_02_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4e 6f 72 6d 61 6c 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 20 22 20 26 20 43 68 72 28 33 38 29 20 26 20 22 20 63 6f 70 79 20 22 20 26 20 [0-0a] 20 26 20 22 20 [0-0a] 2e 76 62 73 22 20 26 20 22 20 22 20 26 20 43 68 72 28 33 38 29 20 26 } //1
		$a_00_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 22 20 20 50 68 79 73 69 63 61 6c 20 28 4d 41 43 29 20 61 64 64 72 65 73 73 3a 20 22 20 26 20 6f 62 6a 41 64 61 70 74 65 72 2e 4d 41 43 41 64 64 72 65 73 73 } //1 .WriteLine "  Physical (MAC) address: " & objAdapter.MACAddress
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}