
rule Trojan_Win32_Zenpak_KAF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 33 ce 8d 45 e4 89 4d fc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}