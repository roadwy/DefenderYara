
rule Trojan_Win32_Vbobfus_RJ_MTB{
	meta:
		description = "Trojan:Win32/Vbobfus.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 00 00 00 00 66 3d 33 c0 ba fc 30 40 00 68 6c 11 40 00 c3 b8 00 00 00 00 66 3d 33 c0 ba 44 5f 40 00 68 6c 11 40 00 c3 } //1
		$a_01_1 = {77 00 6c 00 78 00 6b 00 62 00 79 00 62 00 71 00 2e 00 65 00 78 00 65 00 } //1 wlxkbybq.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}