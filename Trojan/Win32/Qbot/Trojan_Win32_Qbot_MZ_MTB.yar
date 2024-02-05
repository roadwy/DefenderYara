
rule Trojan_Win32_Qbot_MZ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 90 02 04 6a 00 89 90 02 02 29 90 01 01 31 90 01 01 89 90 01 01 5d 31 90 01 01 8b 90 01 02 83 90 01 02 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}