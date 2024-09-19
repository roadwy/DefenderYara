
rule Trojan_Win32_Bayrob_MD_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 89 30 e8 73 f7 ff ff 80 7d fc 00 74 07 8b 45 f8 83 60 70 fd 8b c6 5e 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}