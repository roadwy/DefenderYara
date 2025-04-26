
rule Trojan_Win32_Tofsee_AAG_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.AAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 83 c0 04 f7 da 8d 52 d7 8d 52 fe 42 29 ca 89 d1 c7 47 00 00 00 00 00 31 17 83 c7 04 83 c3 fc 8d 15 ?? ?? ?? ?? 81 ea 65 98 00 00 ff e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}