
rule Trojan_Win32_Chapak_RB_MTB{
	meta:
		description = "Trojan:Win32/Chapak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc f0 43 03 00 83 45 fc 0d a1 90 01 04 0f af 45 fc 05 c3 9e 26 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}