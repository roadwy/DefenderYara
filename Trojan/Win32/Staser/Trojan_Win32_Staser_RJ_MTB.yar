
rule Trojan_Win32_Staser_RJ_MTB{
	meta:
		description = "Trojan:Win32/Staser.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 68 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 5c 90 65 00 56 ff 15 58 90 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}