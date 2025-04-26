
rule Trojan_Win32_Tofsee_BAE_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 83 c0 04 f7 da 8d 52 d7 8d 52 fe 42 29 ca 89 d1 c7 47 00 00 00 00 00 31 17 83 c7 04 83 c3 fc } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}