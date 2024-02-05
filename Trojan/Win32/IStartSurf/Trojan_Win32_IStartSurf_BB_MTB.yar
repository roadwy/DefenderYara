
rule Trojan_Win32_IStartSurf_BB_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 02 32 c1 8b 4d 10 88 04 0e 8b 45 0c } //00 00 
	condition:
		any of ($a_*)
 
}