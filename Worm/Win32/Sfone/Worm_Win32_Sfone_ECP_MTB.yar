
rule Worm_Win32_Sfone_ECP_MTB{
	meta:
		description = "Worm:Win32/Sfone.ECP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e0 1f 50 59 8d 04 8d ?? ?? ?? ?? 8b 10 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1 } //5
		$a_01_1 = {99 f7 f9 89 14 bb 83 c7 01 89 f8 39 f0 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}