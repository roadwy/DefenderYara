
rule Trojan_Win32_LummaStealer_CCHB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 53 57 56 83 ec ?? 8b 4c 24 ?? a1 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d0 40 66 90 90 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}