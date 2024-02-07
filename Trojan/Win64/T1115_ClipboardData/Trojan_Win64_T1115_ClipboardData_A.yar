
rule Trojan_Win64_T1115_ClipboardData_A{
	meta:
		description = "Trojan:Win64/T1115_ClipboardData.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 63 00 6c 00 69 00 70 00 } //00 00  misc::clip
	condition:
		any of ($a_*)
 
}