
rule Trojan_Win32_IStartSurf_VDSK_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.VDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 08 88 4d 0f 8a 04 02 32 c1 8b 4d 18 88 04 0e 8b 45 bc } //02 00 
		$a_01_1 = {89 45 e8 89 7d f8 03 c0 83 f1 3a 8b 45 cc 40 89 7d d4 89 45 cc 3b 45 10 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}