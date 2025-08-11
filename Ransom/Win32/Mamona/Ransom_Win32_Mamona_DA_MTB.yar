
rule Ransom_Win32_Mamona_DA_MTB{
	meta:
		description = "Ransom:Win32/Mamona.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //10 your files have been encrypted
		$a_81_1 = {52 45 41 44 4d 45 2e 48 41 65 73 2e 74 78 74 } //5 README.HAes.txt
		$a_81_2 = {2e 48 41 45 53 } //5 .HAES
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5) >=20
 
}