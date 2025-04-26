
rule Ransom_MSIL_HiddenTear_MKV_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 00 4c 00 6f 00 63 00 6b 00 69 00 66 00 79 00 } //1 .Lockify
		$a_01_1 = {52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 48 00 54 00 41 00 } //1 Readme.HTA
		$a_01_2 = {72 00 2e 00 68 00 74 00 61 00 } //1 r.hta
		$a_01_3 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
		$a_01_4 = {70 61 73 73 77 6f 72 64 42 79 74 65 73 } //1 passwordBytes
		$a_01_5 = {43 72 65 61 74 65 50 61 73 73 77 6f 72 64 } //1 CreatePassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}