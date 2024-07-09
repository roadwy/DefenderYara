
rule Ransom_Win32_StopCrypt_MAK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8b c8 c1 e9 05 03 4c 24 20 03 c7 33 c8 33 4c 24 34 c7 05 [0-08] 89 4c 24 34 8b 44 24 34 01 05 [0-04] 2b f1 8b ce c1 e1 04 03 fe 8b d6 57 8d 44 24 38 03 cb c1 ea 05 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}