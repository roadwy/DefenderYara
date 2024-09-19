
rule Trojan_Win32_Vidar_AMAE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 32 c1 8b 4d ?? 88 04 31 ff 75 ?? ff 45 ?? 46 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}