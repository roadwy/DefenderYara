
rule Trojan_Win32_LummaStealer_AMAE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 31 3b 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}