
rule Trojan_Win32_RenoFloss_B_dha{
	meta:
		description = "Trojan:Win32/RenoFloss.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 ff ff ff ff 90 01 07 31 90 01 01 10 03 90 01 01 10 83 90 01 01 fc 90 09 0a 00 90 90 90 90 90 01 03 c9 66 b9 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}