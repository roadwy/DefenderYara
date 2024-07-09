
rule Ransom_Win32_ContiCrypt_PL_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 ?? ac } //1
		$a_03_1 = {aa 4a 0f 85 [0-04] 8b ec 5d c2 0c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}