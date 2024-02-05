
rule Trojan_Win32_RedLine_RDBV_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 5d e8 0f b6 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 0f b6 4c 0d 10 32 88 } //00 00 
	condition:
		any of ($a_*)
 
}