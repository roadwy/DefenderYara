
rule Trojan_Win32_Staser_RI_MTB{
	meta:
		description = "Trojan:Win32/Staser.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a 29 ff 15 dc 93 65 00 85 c0 a3 e0 ca 65 00 74 0a 8b 45 14 50 ff 15 58 90 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}