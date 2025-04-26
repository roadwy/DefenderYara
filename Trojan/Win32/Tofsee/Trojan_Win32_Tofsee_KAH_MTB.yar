
rule Trojan_Win32_Tofsee_KAH_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 d2 4a 23 17 83 ef fc f7 da 83 ea 26 83 c2 fe 8d 52 01 29 c2 52 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}