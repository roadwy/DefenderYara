
rule Trojan_Win32_Redline_ASBK_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 de 33 f6 33 f3 8b d8 33 f0 8b c3 33 d8 8b f6 f6 2f 47 e2 } //01 00 
		$a_01_1 = {73 6f 68 76 79 6f 70 74 79 74 77 65 69 6c 77 65 66 65 6b 61 66 6e 66 73 72 71 6c 69 67 70 6b 6e 77 71 77 64 61 67 74 75 69 75 72 73 77 67 6f 6e 7a 66 70 63 75 72 65 71 77 } //00 00  sohvyoptytweilwefekafnfsrqligpknwqwdagtuiurswgonzfpcureqw
	condition:
		any of ($a_*)
 
}