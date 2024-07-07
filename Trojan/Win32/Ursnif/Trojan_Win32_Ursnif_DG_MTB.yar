
rule Trojan_Win32_Ursnif_DG_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 10 2b ca 81 3d 90 01 04 d2 0c 00 00 8d 51 fa 75 90 01 01 81 ef d2 0c 00 00 8d 0c 17 8d 14 4d 90 01 04 8b 74 24 0c 8b 4c 24 20 83 44 24 0c 04 81 c1 64 12 02 01 89 0d 90 01 04 89 0e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}