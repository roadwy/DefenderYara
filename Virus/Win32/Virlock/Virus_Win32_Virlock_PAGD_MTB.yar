
rule Virus_Win32_Virlock_PAGD_MTB{
	meta:
		description = "Virus:Win32/Virlock.PAGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c4 c0 03 00 00 c3 e9 ?? ?? ?? ?? 88 07 42 ?? 46 ?? 47 ?? 49 83 f9 } //2
		$a_03_1 = {8b f8 8b df ?? b9 c0 03 00 00 e9 ?? ?? ?? ?? ba 30 00 00 00 8a 06 ?? 32 c2 ?? e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}