
rule Ransom_Win32_StopCrypt_PBN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 03 45 ?? 8b d7 89 45 ?? 8d 04 3e 50 8d 45 ?? c1 ea 05 03 55 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 e8 [0-04] 8b 45 [0-08] 33 c2 29 45 [0-06] 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}