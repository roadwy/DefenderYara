
rule Trojan_Win32_KillFiles_TMX_MTB{
	meta:
		description = "Trojan:Win32/KillFiles.TMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 8d 41 01 fe c9 80 e2 01 0f b6 c0 0f b6 c9 0f 45 c8 8b 45 e4 88 0c 06 46 3b f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}