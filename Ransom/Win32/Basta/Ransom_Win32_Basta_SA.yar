
rule Ransom_Win32_Basta_SA{
	meta:
		description = "Ransom:Win32/Basta.SA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_80_0 = {62 61 73 74 61 } //basta  5
		$a_80_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //vssadmin.exe delete shadows  2
		$a_80_2 = {2d 62 6f 6d 62 } //-bomb  1
		$a_80_3 = {2d 65 6e 63 72 79 70 74 69 6f 6e 70 65 72 63 65 6e 74 } //-encryptionpercent  1
		$a_80_4 = {2d 74 68 72 65 61 64 73 } //-threads  1
		$a_80_5 = {2d 6e 6f 6d 75 74 65 78 } //-nomutex  1
		$a_80_6 = {2d 66 6f 72 63 65 70 61 74 68 } //-forcepath  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=10
 
}