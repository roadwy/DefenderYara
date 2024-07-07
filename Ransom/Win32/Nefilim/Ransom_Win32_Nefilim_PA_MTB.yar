
rule Ransom_Win32_Nefilim_PA_MTB{
	meta:
		description = "Ransom:Win32/Nefilim.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 45 00 4c 00 45 00 47 00 52 00 41 00 4d 00 2d 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 2e 00 74 00 78 00 74 00 } //1 TELEGRAM-RECOVER.txt
		$a_01_1 = {2e 00 54 00 45 00 4c 00 45 00 47 00 52 00 41 00 4d 00 } //1 .TELEGRAM
		$a_01_2 = {5c 00 47 00 4f 00 4f 00 42 00 41 00 2e 00 6a 00 70 00 67 00 } //1 \GOOBA.jpg
		$a_00_3 = {5c 73 6f 73 61 74 27 20 6b 69 6b 69 5c 64 65 76 6b 61 5c 52 65 6c 65 61 73 65 5c 54 45 4c 45 47 52 41 4d 2e 70 64 62 } //1 \sosat' kiki\devka\Release\TELEGRAM.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}