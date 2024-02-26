
rule Trojan_Win32_LummaStealer_EM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 ba } //00 00 
	condition:
		any of ($a_*)
 
}