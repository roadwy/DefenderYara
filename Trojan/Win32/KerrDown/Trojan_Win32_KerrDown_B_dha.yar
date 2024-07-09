
rule Trojan_Win32_KerrDown_B_dha{
	meta:
		description = "Trojan:Win32/KerrDown.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 44 6c 6c 48 69 6a 61 63 6b 2e 64 6c 6c 00 44 6c 6c 45 6e 74 72 79 } //1
		$a_03_1 = {00 44 6c 6c 48 69 6a 61 63 6b 2e 64 6c 6c 00 [0-05] 4d 61 69 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}