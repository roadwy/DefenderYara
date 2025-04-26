
rule Trojan_Win32_IStartSurf_PDK_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PDK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d e0 c1 e9 05 03 4d b4 33 c1 8b 55 e4 2b d0 89 55 e4 8b 45 c8 2b 45 b0 89 45 c8 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}