
rule Trojan_Win32_Ursnif_DHE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6b d2 39 a1 90 01 04 2b c2 a3 90 01 04 8b 0d 90 01 04 6b c9 39 8b 15 90 01 04 2b d1 89 55 ec 8b 45 ec 83 e8 54 33 c9 2b 45 f0 1b 4d f4 a3 90 01 04 8b 15 90 01 04 81 c2 18 6d 0c 02 89 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}