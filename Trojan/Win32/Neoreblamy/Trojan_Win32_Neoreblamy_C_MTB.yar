
rule Trojan_Win32_Neoreblamy_C_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff ff 99 f7 bd ac 90 01 01 ff ff 03 95 24 90 01 01 ff ff 03 95 e0 90 01 01 ff ff 8b c2 99 89 85 30 90 00 } //02 00 
		$a_03_1 = {d3 e0 0b 85 fc 90 01 01 ff ff 99 89 85 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}