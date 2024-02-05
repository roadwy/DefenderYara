
rule Ransom_Win32_StopCrypt_PAD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 a4 36 ef c6 c3 55 8b ec 81 ec 44 08 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}