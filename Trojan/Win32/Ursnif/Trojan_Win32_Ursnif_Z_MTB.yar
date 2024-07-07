
rule Trojan_Win32_Ursnif_Z_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 0f b6 8a 90 01 04 8b 45 90 01 01 99 be 90 01 04 f7 fe 03 15 90 01 04 a1 90 01 04 0f be 94 02 90 01 04 33 ca 8b 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}