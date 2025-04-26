
rule Trojan_Win32_Netwire_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Netwire.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 e4 8d 4d e4 80 75 e5 42 83 c4 04 80 75 e6 42 34 42 80 75 e7 42 88 45 e4 8b 45 dc 6a 00 6a 04 51 8b 40 04 8d 4d dc ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}