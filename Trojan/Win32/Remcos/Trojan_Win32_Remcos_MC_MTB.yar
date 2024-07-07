
rule Trojan_Win32_Remcos_MC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a c8 c0 c9 03 02 c8 d0 c1 02 c8 32 c8 2a c8 80 c1 41 c0 c9 03 80 c1 30 80 f1 d3 80 e9 18 88 88 90 01 04 40 3d 05 4e 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}