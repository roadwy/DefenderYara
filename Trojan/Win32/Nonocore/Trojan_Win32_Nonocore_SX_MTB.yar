
rule Trojan_Win32_Nonocore_SX_MTB{
	meta:
		description = "Trojan:Win32/Nonocore.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 f7 f9 0f af 45 90 01 01 89 45 90 01 01 0f b6 45 90 01 01 33 45 90 01 01 88 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 83 c1 90 01 01 0f af 4d 90 01 01 03 c1 8b 4d 90 01 01 03 4d 90 01 01 c1 e1 90 01 01 2b c1 03 45 90 01 01 89 45 90 01 01 8d 85 90 01 04 85 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}