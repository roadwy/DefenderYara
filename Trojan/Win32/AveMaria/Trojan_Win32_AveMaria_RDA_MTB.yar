
rule Trojan_Win32_AveMaria_RDA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c8 83 c0 3e 89 45 a4 0f be 45 cf 0f b7 c8 0f b7 05 ?? ?? ?? ?? 66 3b c8 8a 45 cf 0f 94 c2 33 c9 3c 48 0f 94 c1 3b d1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}