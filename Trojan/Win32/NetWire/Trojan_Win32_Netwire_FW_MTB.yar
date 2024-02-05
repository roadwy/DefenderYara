
rule Trojan_Win32_Netwire_FW_MTB{
	meta:
		description = "Trojan:Win32/Netwire.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 ff 7e 90 01 01 81 ff 90 01 02 00 00 75 90 01 01 90 02 04 ff 15 90 01 04 e8 90 01 04 30 04 1e 46 3b f7 7c 90 01 01 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}