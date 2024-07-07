
rule Ransom_MSIL_Eraw{
	meta:
		description = "Ransom:MSIL/Eraw,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 66 74 65 72 20 74 68 65 20 70 61 79 6d 65 6e 74 20 68 61 73 20 62 65 65 6e 20 6d 61 64 65 2c 20 73 65 6e 64 20 32 30 20 6e 75 64 65 20 70 69 63 74 75 72 65 73 20 6f 66 } //5 After the payment has been made, send 20 nude pictures of
		$a_01_1 = {74 65 63 68 20 73 75 70 70 6f 72 74 20 65 6d 70 6c 6f 79 65 65 73 20 61 74 20 38 39 37 35 35 36 31 30 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d 2e } //5 tech support employees at 89755610@protonmail.com.
		$a_01_2 = {53 75 63 63 57 61 72 65 2e 65 78 65 } //5 SuccWare.exe
		$a_01_3 = {53 00 65 00 6e 00 64 00 20 00 6d 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 6e 00 75 00 64 00 65 00 73 00 20 00 66 00 69 00 72 00 73 00 74 00 } //5 Send me your nudes first
		$a_01_4 = {6b 00 69 00 6c 00 20 00 79 00 6f 00 72 00 73 00 65 00 6c 00 66 00 20 00 66 00 61 00 67 00 6f 00 74 00 } //5 kil yorself fagot
		$a_01_5 = {43 3a 5c 53 75 63 63 57 61 72 65 5c 53 75 63 63 57 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 75 63 63 57 61 72 65 2e 70 64 62 } //25 C:\SuccWare\SuccWare\obj\Debug\SuccWare.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*25) >=20
 
}