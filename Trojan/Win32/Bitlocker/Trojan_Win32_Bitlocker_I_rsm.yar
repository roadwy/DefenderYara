
rule Trojan_Win32_Bitlocker_I_rsm{
	meta:
		description = "Trojan:Win32/Bitlocker.I!rsm,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6d 00 61 00 6e 00 61 00 67 00 65 00 2d 00 62 00 64 00 65 00 90 02 12 2d 00 6f 00 6e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}