
rule Trojan_Win32_Fareit_OTYT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.OTYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 03 d3 8a 12 80 f2 56 8b 4d fc 03 c8 88 11 ff 45 fc 81 7d fc 9a 59 00 00 75 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}