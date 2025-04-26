
rule Trojan_Win32_IStartSurf_PDSK_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d ff 8a 04 02 32 c1 8b 4d 10 88 04 0e 8b 45 0c 89 45 e4 8b 45 c8 89 45 f4 83 ca 76 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}