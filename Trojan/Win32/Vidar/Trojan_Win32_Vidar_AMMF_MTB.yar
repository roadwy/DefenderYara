
rule Trojan_Win32_Vidar_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 31 18 83 45 90 01 02 6a 00 e8 90 01 04 83 c0 90 01 01 01 45 90 01 01 8b 45 90 01 01 3b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}