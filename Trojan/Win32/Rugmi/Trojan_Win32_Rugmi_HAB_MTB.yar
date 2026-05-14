
rule Trojan_Win32_Rugmi_HAB_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 83 7d f8 00 75 02 eb 90 09 40 00 [0-3f] 55 8b ec [0-20] c7 45 [0-20] 89 45 f8 83 7d f8 00 75 02 eb ?? 8b 55 fc 8b [0-04] 03 45 f8 89 45 f4 ff 55 f4 90 90 8b e5 5d c3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}