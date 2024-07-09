
rule Trojan_Win32_MuddyRope_C{
	meta:
		description = "Trojan:Win32/MuddyRope.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 50 50 44 41 54 41 [0-10] 5c 4c 69 62 2e 70 73 31 [0-19] 68 74 74 70 3a 2f 2f [0-2a] 2e 64 61 74 [0-30] 2d 65 78 65 63 [0-05] 62 79 70 61 73 73 [0-08] 50 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 [0-06] 4f 70 65 6e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}