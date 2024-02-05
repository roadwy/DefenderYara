
rule Trojan_Win32_Ekstak_EM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 e8 90 01 04 68 38 9c 65 00 c7 05 38 9c 65 00 44 00 00 00 ff 15 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}