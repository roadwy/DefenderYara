
rule Trojan_Win32_Ursnif_DHF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 8b c8 8b f2 8b 44 24 28 99 03 c1 8b 4c 24 14 13 f2 2b 44 24 10 89 44 24 10 1b f7 a3 90 01 04 a1 90 01 04 8b fe 89 74 24 18 8b 74 24 28 89 3d 90 01 04 8b 54 24 20 89 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}