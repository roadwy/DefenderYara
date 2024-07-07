
rule Trojan_Win32_WarZone_RDA_MTB{
	meta:
		description = "Trojan:Win32/WarZone.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 99 f7 ff 8a 44 15 98 30 04 31 41 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}