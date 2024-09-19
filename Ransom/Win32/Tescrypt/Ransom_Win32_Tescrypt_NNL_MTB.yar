
rule Ransom_Win32_Tescrypt_NNL_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.NNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {64 74 6e 74 74 6a 74 6b 64 74 79 6a 74 } //3 dtnttjtkdtyjt
		$a_81_1 = {73 75 70 70 65 6b 53 74 72 } //2 suppekStr
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2) >=5
 
}