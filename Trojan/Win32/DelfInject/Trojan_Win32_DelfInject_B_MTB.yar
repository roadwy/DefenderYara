
rule Trojan_Win32_DelfInject_B_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 ?? ff 45 fc 41 89 d3 39 d9 90 90 90 90 75 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}