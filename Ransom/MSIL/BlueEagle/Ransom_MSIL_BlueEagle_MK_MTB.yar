
rule Ransom_MSIL_BlueEagle_MK_MTB{
	meta:
		description = "Ransom:MSIL/BlueEagle.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {42 6c 75 65 5f 45 61 67 6c 65 5f 52 61 6e 73 6f 6d 77 61 72 65 } //Blue_Eagle_Ransomware  1
		$a_80_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //RijndaelManaged  1
		$a_80_2 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //Rfc2898DeriveBytes  1
		$a_80_3 = {52 61 6e 73 6f 6d 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 } //Ransomware.Resources  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}