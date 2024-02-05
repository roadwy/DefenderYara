
rule Ransom_Win32_StopCrypt_PR_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 55 8b ec 83 ec 0c } //01 00 
		$a_01_1 = {c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 55 8b ec 81 ec 28 0c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}