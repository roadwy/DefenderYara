
rule Trojan_Win32_Ursnif_RW_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.RW!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 49 65 2e 79 2d 4b 5a 58 2d 4c 75 6a 70 6d 2d 4b 77 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}