
rule Trojan_Win32_Bayrob_MH_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 11 c7 45 fc fe ff ff ff b8 ff 00 00 00 e9 04 01 00 00 68 14 62 49 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}