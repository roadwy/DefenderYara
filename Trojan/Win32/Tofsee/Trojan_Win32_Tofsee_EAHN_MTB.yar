
rule Trojan_Win32_Tofsee_EAHN_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 d2 33 13 83 c3 04 f7 da 8d 52 d7 8d 52 fe 83 ea ff 29 ca 31 c9 31 d1 c7 46 00 00 00 00 00 31 16 83 ee fc 83 c7 fc 8d 15 ?? ?? ?? ?? 81 ea 65 98 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}