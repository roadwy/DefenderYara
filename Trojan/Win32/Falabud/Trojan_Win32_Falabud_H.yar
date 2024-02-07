
rule Trojan_Win32_Falabud_H{
	meta:
		description = "Trojan:Win32/Falabud.H,SIGNATURE_TYPE_CMDHSTR_EXT,5a 00 5a 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //0a 00  mshta
		$a_00_1 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 } //0a 00  vbscript
		$a_00_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //0a 00  wscript
		$a_00_3 = {73 00 68 00 65 00 6c 00 6c 00 } //0a 00  shell
		$a_00_4 = {72 00 75 00 6e 00 } //0a 00  run
		$a_00_5 = {66 00 6f 00 72 00 } //0a 00  for
		$a_00_6 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //0a 00  msiexec
		$a_00_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //0a 00  http://
		$a_00_8 = {77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 63 00 6c 00 6f 00 73 00 65 00 } //00 00  window.close
	condition:
		any of ($a_*)
 
}