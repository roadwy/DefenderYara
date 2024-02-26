
rule Trojan_Win32_Mint_NBL_MTB{
	meta:
		description = "Trojan:Win32/Mint.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 8a 81 90 01 03 00 c0 c8 03 32 83 90 01 03 00 88 81 90 01 03 00 8d 43 01 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  01 00 
		$a_80_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  00 00 
	condition:
		any of ($a_*)
 
}