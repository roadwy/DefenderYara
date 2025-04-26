
rule Ransom_Win32_Conti_AC_MTB{
	meta:
		description = "Ransom:Win32/Conti.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 c0 e0 ?? 0a c8 c0 e1 ?? 8a 46 ?? 24 ?? 0a c8 88 0c ?? 42 8d 76 ?? 81 fa ?? ?? ?? ?? 7d ?? 8b 90 0a 30 00 8a 4e ?? 80 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}