
rule Trojan_Win32_Staser_BX_MTB{
	meta:
		description = "Trojan:Win32/Staser.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 3b 7d 0c a9 00 00 80 00 6a 14 6a 40 ff 15 [0-04] 8b f0 6a 01 56 ff 15 [0-04] e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}