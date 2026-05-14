
rule Trojan_Win32_SuspSysCallFind_A{
	meta:
		description = "Trojan:Win32/SuspSysCallFind.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 04 25 08 03 fe 7f 01 } //1
		$a_03_1 = {75 03 0f 05 c3 cd 2e c3 ?? ?? 4c 8b d1 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}