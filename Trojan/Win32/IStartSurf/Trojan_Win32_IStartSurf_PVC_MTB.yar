
rule Trojan_Win32_IStartSurf_PVC_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 14 8a 04 02 8b 55 10 32 c1 88 04 16 0f be f1 8b c6 c1 f8 02 83 e0 0f 83 f8 04 0f 83 } //00 00 
	condition:
		any of ($a_*)
 
}