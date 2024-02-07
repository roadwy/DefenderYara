
rule Trojan_AndroidOS_SharkBot_U{
	meta:
		description = "Trojan:AndroidOS/SharkBot.U,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 4d 65 78 66 45 6e 42 5a 41 37 71 37 69 5a 4d 75 55 50 45 32 62 70 57 57 71 37 64 5a 58 4c 32 75 72 57 2b 7a 39 37 64 70 63 68 71 57 68 34 68 57 4f 67 55 6e 62 43 6b 34 7a 2b 48 62 7a 61 38 } //01 00  +MexfEnBZA7q7iZMuUPE2bpWWq7dZXL2urW+z97dpchqWh4hWOgUnbCk4z+Hbza8
		$a_01_1 = {4c 4d 44 4f 76 65 72 6c 61 79 20 6e 6f 74 20 62 6f 75 6e 64 } //01 00  LMDOverlay not bound
		$a_01_2 = {73 68 6f 77 20 68 69 64 64 65 6e 20 66 69 6c 65 } //01 00  show hidden file
		$a_01_3 = {7b 75 70 6c 6f 61 64 2d 75 72 6c 7d } //00 00  {upload-url}
	condition:
		any of ($a_*)
 
}