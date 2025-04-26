
rule Trojan_Win32_Lazy_RF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 4a 52 8b 45 fc 83 c0 31 8b 0d ?? ?? ?? ?? 66 89 41 54 8b 55 fc 83 c2 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}