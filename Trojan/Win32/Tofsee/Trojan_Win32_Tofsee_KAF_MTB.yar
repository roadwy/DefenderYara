
rule Trojan_Win32_Tofsee_KAF_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 83 c6 ?? 83 c0 ?? 01 d0 83 e8 ?? 31 d2 09 c2 c6 01 ?? 01 01 83 c1 ?? 83 c7 ?? 81 ff 88 06 00 00 75 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}