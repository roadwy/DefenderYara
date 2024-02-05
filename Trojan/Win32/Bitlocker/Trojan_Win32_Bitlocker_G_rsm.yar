
rule Trojan_Win32_Bitlocker_G_rsm{
	meta:
		description = "Trojan:Win32/Bitlocker.G!rsm,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {61 00 74 00 74 00 72 00 69 00 62 00 2e 00 65 00 78 00 65 00 90 02 04 2d 00 73 00 20 00 2d 00 68 00 20 00 90 02 30 2a 00 2e 00 42 00 45 00 4b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}