
rule Trojan_Win32_Zusy_GNS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 f7 89 f0 31 db 83 c7 58 81 2e 90 01 04 83 c6 04 66 ba 90 01 02 39 fe 7c 90 01 01 66 be 90 01 02 bb 90 01 04 53 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}