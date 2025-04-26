
rule Trojan_Win32_FatalRat_RPY_MTB{
	meta:
		description = "Trojan:Win32/FatalRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 1b c0 23 c6 68 a9 40 00 00 50 8d 4d d8 ff d7 85 c0 74 c3 6a 00 6a 04 8d 45 ec c7 45 ec 00 00 00 00 50 8d 4d d8 ff d3 85 c0 7e ab } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}