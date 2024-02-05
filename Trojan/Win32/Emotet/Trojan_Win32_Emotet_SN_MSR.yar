
rule Trojan_Win32_Emotet_SN_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 73 67 6a 68 67 68 6a 66 64 46 41 44 5a 78 63 52 46 54 } //02 00 
		$a_01_1 = {63 7a 73 73 64 6b 67 6e 62 6e 47 44 46 66 72 74 79 61 58 6c } //01 00 
		$a_02_2 = {50 72 6f 6a 65 63 74 90 02 02 2e 65 78 65 90 00 } //01 00 
		$a_01_3 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}