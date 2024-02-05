
rule Trojan_Win32_Dridex_GN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 cf 36 ea 2e 5d 90 02 06 0f b6 fc 29 f9 88 cc 88 65 90 01 01 8b 4d 90 01 01 8b 7d 90 01 01 8a 65 90 01 01 88 24 0f 88 45 90 01 01 89 75 90 01 01 89 55 90 01 01 83 c4 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}