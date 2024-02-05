
rule Trojan_Win32_Qbot_MY_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 90 02 04 57 33 90 02 02 09 90 01 01 83 90 02 02 09 90 01 01 5f 81 90 02 05 33 90 02 02 83 90 02 02 aa 49 75 90 00 } //01 00 
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff 90 02 05 8f 90 02 02 ff 90 02 02 58 81 90 02 05 33 90 02 02 83 90 02 02 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}