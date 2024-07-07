
rule Ransom_Win32_StopCrypt_PC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}