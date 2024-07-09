
rule Ransom_Win32_VSocCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/VSocCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 18 88 4b ?? 8b 8d [0-04] 8b c1 c1 e8 08 88 43 ?? 8b c1 c1 e8 10 88 43 ?? 8b c2 c1 e8 08 88 4b ?? c1 e9 18 88 43 ?? 8b c2 88 ?? 3b 8b 4d 14 88 53 ?? c1 e8 10 c1 ea 18 88 43 ?? 88 53 ?? 83 f9 ?? 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}