
rule Trojan_Win32_Ursnif_GXB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 8b 71 14 8b d6 2b d0 2b 54 24 08 8a 12 88 16 8d 50 01 01 51 14 83 ca ff 2b d0 01 54 24 0c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}