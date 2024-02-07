
rule Ransom_Win32_LockCrypt_PD_MTB{
	meta:
		description = "Ransom:Win32/LockCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 42 6e 79 61 72 38 52 73 4b 30 34 75 67 2f } //01 00  /Bnyar8RsK04ug/
		$a_01_1 = {2f 42 6e 70 4f 6e 73 70 51 77 74 6a 43 41 2f 72 65 67 69 73 74 65 72 } //01 00  /BnpOnspQwtjCA/register
		$a_01_2 = {31 37 33 2e 32 33 32 2e 31 34 36 2e 31 31 38 } //01 00  173.232.146.118
		$a_01_3 = {52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 46 00 4f 00 52 00 5f 00 } //00 00  README_FOR_
	condition:
		any of ($a_*)
 
}