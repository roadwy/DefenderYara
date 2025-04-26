
rule Trojan_Win32_Ursnif_RU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 20 00 8b c3 99 2b c2 56 d1 f8 89 4d fc 57 8b c8 89 5d f4 33 f6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}