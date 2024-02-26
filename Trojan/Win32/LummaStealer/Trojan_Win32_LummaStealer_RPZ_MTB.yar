
rule Trojan_Win32_LummaStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f3 f6 17 8b c6 8b f3 33 db 33 f6 33 db 33 f6 8b f6 8b f3 33 f3 80 07 75 8b de } //00 00 
	condition:
		any of ($a_*)
 
}