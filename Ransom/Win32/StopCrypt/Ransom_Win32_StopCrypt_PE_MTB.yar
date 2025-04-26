
rule Ransom_Win32_StopCrypt_PE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 ?? 8b 08 33 4d ?? 8b 55 ?? 89 0a 5d } //1
		$a_03_1 = {c1 e2 04 89 ?? e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-0a] c7 05 [0-0a] 8b ?? f4 8b 8d [0-04] d3 ?? 89 ?? ec 8b ?? ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}