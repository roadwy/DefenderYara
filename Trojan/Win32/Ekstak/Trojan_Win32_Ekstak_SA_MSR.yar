
rule Trojan_Win32_Ekstak_SA_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 4e 2c 8a 1c 28 51 ff 57 08 8a 54 24 1c 02 c3 32 c2 8b 15 90 01 03 00 88 04 2a 8b 44 24 18 83 f8 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}