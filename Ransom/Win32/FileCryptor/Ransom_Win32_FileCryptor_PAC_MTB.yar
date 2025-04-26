
rule Ransom_Win32_FileCryptor_PAC_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 08 33 c7 bf ff 00 00 00 c1 e0 08 33 c3 c1 e0 08 33 45 fc 89 04 b5 90 b4 41 00 c1 c0 08 89 04 b5 90 b0 41 00 c1 c0 08 89 04 b5 90 c0 41 00 c1 c0 08 89 04 b5 68 a3 41 00 46 81 fe 00 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}