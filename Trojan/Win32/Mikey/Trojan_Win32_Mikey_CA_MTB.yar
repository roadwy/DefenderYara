
rule Trojan_Win32_Mikey_CA_MTB{
	meta:
		description = "Trojan:Win32/Mikey.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ce 33 c9 33 35 90 02 04 3b d0 1b d2 83 e2 90 02 04 83 c2 90 02 04 41 89 30 8d 40 04 3b ca 75 f6 90 00 } //01 00 
		$a_01_1 = {33 f0 d3 ce 3b f7 74 69 } //01 00 
		$a_01_2 = {57 65 20 61 72 65 20 62 65 69 6e 67 20 68 65 72 65 } //01 00  We are being here
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}