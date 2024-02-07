
rule Trojan_Win32_Zonsterarch_X{
	meta:
		description = "Trojan:Win32/Zonsterarch.X,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {14 00 00 00 53 65 74 50 72 6f 63 65 73 73 44 45 50 } //0a 00 
		$a_00_1 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //01 00  㜷⌧ጝ㤤潮煰牲牲牲瑳杞幵甤敨牴牲牲
		$a_02_2 = {d9 45 ec d8 90 01 04 00 df e0 9e 77 44 d9 45 ec d8 90 01 04 00 d9 5d ec d9 45 ec 51 d9 1c 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}