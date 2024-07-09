
rule Ransom_MSIL_ArcbornCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/ArcbornCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 } //1 taskmgr
		$a_01_1 = {53 00 61 00 6c 00 62 00 61 00 65 00 6c 00 68 00 4e 00 63 00 63 00 50 00 64 00 51 00 41 00 65 00 6d 00 4f 00 65 00 57 00 } //1 SalbaelhNccPdQAemOeW
		$a_03_2 = {5c 41 72 63 61 6e 65 2d 52 65 62 6f 72 6e 5c [0-10] 5c 41 72 63 61 6e 65 2d 52 65 62 6f 72 6e 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}