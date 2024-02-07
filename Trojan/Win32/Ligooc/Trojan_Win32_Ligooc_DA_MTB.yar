
rule Trojan_Win32_Ligooc_DA_MTB{
	meta:
		description = "Trojan:Win32/Ligooc.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {3f 50 6f 73 74 52 74 6d 40 40 59 41 48 58 5a } //01 00  ?PostRtm@@YAHXZ
		$a_81_1 = {53 65 74 54 69 6d 65 72 } //01 00  SetTimer
		$a_81_2 = {4b 69 6c 6c 54 69 6d 65 72 } //01 00  KillTimer
		$a_81_3 = {47 65 74 43 6c 69 65 6e 74 52 65 63 74 } //01 00  GetClientRect
		$a_81_4 = {53 65 6e 64 4d 65 73 73 61 67 65 41 } //01 00  SendMessageA
		$a_81_5 = {47 65 74 43 6c 61 73 73 4e 61 6d 65 41 } //01 00  GetClassNameA
		$a_81_6 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //00 00  GetCurrentThreadId
	condition:
		any of ($a_*)
 
}