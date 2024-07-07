
rule Trojan_Win32_Cryptinject_PVG_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.PVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8d 34 07 e8 90 01 04 30 06 47 3b 7d 0c 7c 90 00 } //1
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 ec 08 04 00 00 a3 90 01 04 3d ac 61 ef 01 75 90 09 05 00 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}