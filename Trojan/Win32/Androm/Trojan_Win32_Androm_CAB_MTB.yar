
rule Trojan_Win32_Androm_CAB_MTB{
	meta:
		description = "Trojan:Win32/Androm.CAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 1c 10 8a 1b 32 d9 8d 34 02 88 1e 42 81 90 01 05 75 90 00 } //01 00 
		$a_81_1 = {53 65 74 42 6f 75 6e 64 73 52 65 63 74 } //00 00  SetBoundsRect
	condition:
		any of ($a_*)
 
}