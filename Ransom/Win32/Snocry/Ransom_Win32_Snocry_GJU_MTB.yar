
rule Ransom_Win32_Snocry_GJU_MTB{
	meta:
		description = "Ransom:Win32/Snocry.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 56 68 f4 6d 41 00 c6 05 ?? ?? ?? ?? 57 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 4d c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6d c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 79 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}