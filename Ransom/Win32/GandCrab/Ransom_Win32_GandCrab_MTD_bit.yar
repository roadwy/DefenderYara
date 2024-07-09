
rule Ransom_Win32_GandCrab_MTD_bit{
	meta:
		description = "Ransom:Win32/GandCrab.MTD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 6a 64 6a 00 ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? c6 46 ?? ?? 8b c6 5e c3 } //1
		$a_03_1 = {55 8b ec 8b c1 c1 e0 04 03 c2 8b d1 03 4d ?? c1 ea 05 03 55 ?? 33 c2 33 c1 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}