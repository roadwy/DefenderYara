
rule Trojan_Win32_Staser_BW_MTB{
	meta:
		description = "Trojan:Win32/Staser.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 3b 7d 0c a9 00 00 80 00 57 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}