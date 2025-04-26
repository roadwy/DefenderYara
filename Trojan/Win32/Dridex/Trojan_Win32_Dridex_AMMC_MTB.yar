
rule Trojan_Win32_Dridex_AMMC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {42 6f 65 6e 7a 69 65 65 6c 69 6f 61 72 68 68 68 49 } //BoenzieelioarhhhI  2
		$a_80_1 = {69 6e 64 73 71 64 72 71 35 30 2e 64 6c 6c } //indsqdrq50.dll  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}