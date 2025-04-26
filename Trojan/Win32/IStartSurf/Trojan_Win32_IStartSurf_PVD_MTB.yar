
rule Trojan_Win32_IStartSurf_PVD_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 04 02 8b 55 20 32 04 11 8b 55 18 88 04 11 8b 45 b4 89 45 bc } //2
		$a_01_1 = {8a 0c 02 8b 45 20 8a 04 06 32 c1 8b 4d 18 88 04 0e 8b 45 b4 89 45 d4 8b 45 cc 89 45 ec } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}