
rule Ransom_MSIL_Cryptolocker_EX_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 4d 61 67 69 78 2e 65 78 65 } //1 \Windows\Temp\Magix.exe
		$a_81_1 = {76 69 64 65 6f 5f 70 72 6f 5f 78 2e 65 78 65 } //1 video_pro_x.exe
		$a_81_2 = {6f 70 68 6f 73 } //1 ophos
		$a_81_3 = {6b 61 73 70 65 72 73 6b 79 } //1 kaspersky
		$a_81_4 = {6e 6f 72 74 6f 6e } //1 norton
		$a_81_5 = {43 72 61 63 6b 47 65 6e } //1 CrackGen
		$a_81_6 = {2f 5f 2f 5f 2f 5f 2f 5f 2f 5f 2f } //1 /_/_/_/_/_/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}