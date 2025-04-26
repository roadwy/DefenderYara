
rule Ransom_Win32_StopCrypt_PF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 c8 c1 fa 05 8b 45 c8 83 e0 1f c1 e0 06 03 [0-06] 89 45 c0 eb [0-04] c7 45 ?? ?? 7b 42 00 8b 4d c0 8a 51 24 d0 e2 d0 fa 0f be c2 85 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}