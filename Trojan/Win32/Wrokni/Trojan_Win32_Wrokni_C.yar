
rule Trojan_Win32_Wrokni_C{
	meta:
		description = "Trojan:Win32/Wrokni.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 77 6f 72 6b 69 6e 00 } //01 00  搮汬眀牯楫n
		$a_02_1 = {73 65 6c 65 63 74 90 02 40 77 68 65 72 65 20 73 69 67 6e 6f 6e 5f 72 65 61 6c 6d 20 6c 69 6b 65 90 00 } //01 00 
		$a_02_2 = {73 65 6c 65 63 74 90 02 40 66 72 6f 6d 20 63 6f 6f 6b 69 65 73 20 77 68 65 72 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}