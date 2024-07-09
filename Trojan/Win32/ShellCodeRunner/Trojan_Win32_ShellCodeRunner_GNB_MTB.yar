
rule Trojan_Win32_ShellCodeRunner_GNB_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 3e 43 6a 00 ff 15 ?? ?? ?? ?? b8 cd cc cc cc f7 e6 c1 ea 02 8d 0c 92 8b d6 2b d1 75 02 33 db 46 81 fe 00 00 10 00 7c d0 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}