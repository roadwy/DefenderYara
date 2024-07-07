
rule Trojan_Win32_UrSnif_RPM_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 fc 8a 02 0c 01 0f b6 c8 89 d8 99 f7 f9 0f b6 0e 01 c8 88 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}