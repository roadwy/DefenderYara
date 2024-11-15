
rule Trojan_Win32_Tofsee_KAB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 08 83 e8 ?? f7 d9 83 e9 29 83 c1 ?? 8d 49 ?? 29 d1 31 d2 4a 21 ca c7 47 ?? ?? ?? ?? ?? 31 0f 83 c7 04 83 ee 04 83 fe 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}