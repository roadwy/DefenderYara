
rule Ransom_Win32_FileCoder_B{
	meta:
		description = "Ransom:Win32/FileCoder.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 20 77 69 6c 6c 20 62 65 20 75 6e 6c 6f 63 6b 65 64 20 61 75 74 6f 6d 61 74 69 63 6c 6c 79 } //01 00  Your file will be unlocked automaticlly
		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 55 78 64 45 76 65 6e 74 5f 41 50 49 5f 53 65 72 76 69 63 65 } //01 00  \\.\pipe\UxdEvent_API_Service
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 30 2e 31 30 33 2e 32 2e 32 34 37 } //00 00  http://10.103.2.247
	condition:
		any of ($a_*)
 
}