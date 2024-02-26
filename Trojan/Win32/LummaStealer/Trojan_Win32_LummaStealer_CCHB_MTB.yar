
rule Trojan_Win32_LummaStealer_CCHB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 53 57 56 83 ec 90 01 01 8b 4c 24 90 01 01 a1 90 01 04 ba 90 01 04 33 15 90 01 04 01 d0 40 66 90 90 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}