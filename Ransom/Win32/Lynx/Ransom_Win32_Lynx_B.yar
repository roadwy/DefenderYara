
rule Ransom_Win32_Lynx_B{
	meta:
		description = "Ransom:Win32/Lynx.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 2a 00 5d 00 20 00 53 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 66 00 75 00 6c 00 6c 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 35 00 73 00 } //1 [*] Starting full encryption in 5s
		$a_01_1 = {5c 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 6a 00 70 00 67 00 } //1 \background-image.jpg
		$a_01_2 = {54 4f 52 20 4e 65 74 77 6f 72 6b 3a 20 68 74 74 70 3a 2f 2f 6c 79 6e 78 } //1 TOR Network: http://lynx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}