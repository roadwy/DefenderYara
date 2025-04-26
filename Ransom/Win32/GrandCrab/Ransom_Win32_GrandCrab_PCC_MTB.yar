
rule Ransom_Win32_GrandCrab_PCC_MTB{
	meta:
		description = "Ransom:Win32/GrandCrab.PCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 73 20 69 73 20 72 75 6e 6e 69 6e 67 2e 2e 2e } //1 Kis is running...
		$a_01_1 = {61 76 6f 69 64 69 6e 67 20 73 61 6e 64 62 6f 78 20 62 79 20 73 6c 65 65 70 69 6e 67 20 36 30 20 73 65 63 73 } //1 avoiding sandbox by sleeping 60 secs
		$a_01_2 = {46 2d 53 65 63 75 72 65 20 65 69 74 68 65 72 20 53 79 6d 61 6e 74 65 63 20 69 73 20 72 75 6e 6e 69 6e 67 } //1 F-Secure either Symantec is running
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 43 00 6f 00 6d 00 6f 00 64 00 6f 00 } //1 Disable Comodo
		$a_01_4 = {47 00 61 00 6e 00 64 00 43 00 72 00 61 00 62 00 21 00 } //1 GandCrab!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}