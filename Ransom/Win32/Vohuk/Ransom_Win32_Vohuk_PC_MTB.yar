
rule Ransom_Win32_Vohuk_PC_MTB{
	meta:
		description = "Ransom:Win32/Vohuk.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 ?? 89 85 ?? ?? ?? ?? 33 c2 c1 c0 ?? 89 45 ?? 89 45 ?? 03 c1 33 f8 89 45 ?? 89 45 ?? 8b 45 ?? c1 c7 07 89 7d d8 89 bd ?? ?? ?? ?? 8b 7d ec 03 c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}