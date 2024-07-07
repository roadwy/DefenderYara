
rule Trojan_Win32_Ursnif_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 55 fe 8a d6 80 e2 f0 88 75 ff c0 e2 02 0a 14 90 01 01 88 55 fd 8a d6 80 e2 fc c0 e2 04 0a 54 90 01 01 01 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}