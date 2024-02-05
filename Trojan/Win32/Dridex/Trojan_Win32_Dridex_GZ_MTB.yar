
rule Trojan_Win32_Dridex_GZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 0e 81 c1 90 01 04 89 0e 89 0d 90 01 04 8b ca 2b cf 69 c9 90 01 04 02 db 2a 1d 90 01 04 66 03 c1 02 1d 90 01 04 83 c6 04 80 c3 90 01 01 83 ed 01 66 a3 90 01 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}