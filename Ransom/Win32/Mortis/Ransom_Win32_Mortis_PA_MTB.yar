
rule Ransom_Win32_Mortis_PA_MTB{
	meta:
		description = "Ransom:Win32/Mortis.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4d 6f 72 74 69 73 } //1 .Mortis
		$a_01_1 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4d 6f 72 74 69 73 4c 6f 63 6b 65 72 } //1 Your data has been stolen and encrypted by MortisLocker
		$a_01_2 = {5c 4d 6f 72 74 69 73 4c 6f 63 6b 65 72 2e 70 64 62 } //1 \MortisLocker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}