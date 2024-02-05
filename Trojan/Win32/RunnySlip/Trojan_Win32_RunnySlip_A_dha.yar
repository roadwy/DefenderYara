
rule Trojan_Win32_RunnySlip_A_dha{
	meta:
		description = "Trojan:Win32/RunnySlip.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 6f 77 73 2d 6d 61 6e 69 66 65 73 74 2d 66 69 6c 65 6e 61 6d 65 20 6c 69 51 75 69 64 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}