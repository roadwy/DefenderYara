
rule Trojan_Win32_Sefnit_BS{
	meta:
		description = "Trojan:Win32/Sefnit.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c0 06 89 45 ec 8b 4d 0c 8b 51 10 89 55 c8 8b 45 c8 83 e8 01 89 45 f0 8b 4d 0c 83 79 14 08 72 0d } //01 00 
		$a_01_1 = {2d 00 2d 00 61 00 70 00 70 00 3d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}