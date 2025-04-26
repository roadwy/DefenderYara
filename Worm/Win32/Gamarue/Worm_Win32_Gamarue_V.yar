
rule Worm_Win32_Gamarue_V{
	meta:
		description = "Worm:Win32/Gamarue.V,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 d1 80 c2 42 88 14 30 46 3b 35 ?? ?? ?? ?? 72 e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}