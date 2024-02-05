
rule HackTool_Win32_Mimikatz_NPTT{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40 } //kerberos::ptt �@@  01 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Mimikatz_NPTT_2{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 6b 75 72 6c 73 61 3a 3a 74 69 63 6b 65 74 73 20 2f 65 78 70 6f 72 74 } //sekurlsa::tickets /export  01 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Mimikatz_NPTT_3{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_80_0 = {6c 73 61 64 75 6d 70 3a 3a 64 63 73 79 6e 63 } //lsadump::dcsync  01 00 
		$a_80_1 = {2f 75 73 65 72 } ///user  01 00 
		$a_80_2 = {2f 64 6f 6d 61 69 6e } ///domain  01 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Mimikatz_NPTT_4{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_80_0 = {6b 65 72 62 65 72 6f 73 3a 3a 67 6f 6c 64 65 6e } //kerberos::golden  01 00 
		$a_80_1 = {2f 75 73 65 72 } ///user  01 00 
		$a_80_2 = {2f 64 6f 6d 61 69 6e } ///domain  01 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Mimikatz_NPTT_5{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 90 02 40 40 00 90 00 } //01 00 
		$a_02_1 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40 90 00 } //01 00 
		$a_02_2 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 90 02 40 2e 00 6b 00 69 00 72 00 62 00 69 00 90 00 } //01 00 
		$a_02_3 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 2e 6b 69 72 62 69 90 00 } //01 00 
		$a_02_4 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 90 01 01 3a 00 5c 00 90 00 } //01 00 
		$a_02_5 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 01 01 3a 5c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}