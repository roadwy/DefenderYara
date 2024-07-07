
rule Trojan_Win32_Vidar_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 90 01 01 31 10 90 02 0a 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}