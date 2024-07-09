
rule Ransom_Win32_Nokonoko_PD_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4e 44 35 ?? ?? ?? ?? 01 46 5c a1 ?? ?? ?? ?? 8b 55 14 c1 ea 08 88 14 08 ff 46 44 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 55 14 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}