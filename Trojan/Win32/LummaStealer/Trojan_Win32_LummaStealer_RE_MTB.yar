
rule Trojan_Win32_LummaStealer_RE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04 0f be d2 66 89 14 4f 41 39 c8 75 e7 } //00 00 
	condition:
		any of ($a_*)
 
}