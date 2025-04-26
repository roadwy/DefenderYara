
rule Trojan_Win32_Ursnif_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 29 02 03 cd 88 44 24 12 8a 59 03 8a c3 24 f0 c0 e0 02 0a 01 88 44 24 13 a1 ?? ?? ?? ?? 3d e9 05 00 00 0f } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}