
rule Trojan_Win32_CobaltStrike_ST_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 34 39 2e 32 33 34 2e 36 35 2e 35 32 2f 55 70 64 61 74 65 53 74 72 65 61 6d 5f 78 38 36 2e 63 61 62 } //01 00  http://49.234.65.52/UpdateStream_x86.cab
		$a_81_1 = {73 68 65 6c 6c 63 6f 64 65 20 61 64 64 72 65 73 73 } //01 00  shellcode address
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_81_3 = {43 61 6c 6c 42 61 63 6b 48 65 6c 70 65 72 } //01 00  CallBackHelper
		$a_81_4 = {57 72 69 74 65 4c 69 6e 65 } //00 00  WriteLine
	condition:
		any of ($a_*)
 
}