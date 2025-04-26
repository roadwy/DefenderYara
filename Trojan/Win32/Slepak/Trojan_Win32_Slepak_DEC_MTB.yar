
rule Trojan_Win32_Slepak_DEC_MTB{
	meta:
		description = "Trojan:Win32/Slepak.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c0 2b c1 05 c5 8f 00 00 03 c3 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 80 c3 5c 02 da 02 da 88 1d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}