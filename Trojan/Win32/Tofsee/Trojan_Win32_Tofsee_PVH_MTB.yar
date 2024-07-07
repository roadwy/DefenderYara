
rule Trojan_Win32_Tofsee_PVH_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 cc fb ff ff 8b 4d fc 89 38 5f 89 70 04 5e 33 cd 5b e8 90 01 04 8b e5 5d c2 04 00 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}