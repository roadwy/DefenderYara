
rule Trojan_Win32_Clipbanker_xyzw_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.xyzw!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 87 ac 47 ab 80 29 76 b3 66 f2 32 49 80 1d 90 91 3a 04 33 73 28 } //0a 00 
		$a_01_1 = {d2 30 32 e9 28 16 09 9a 1d a4 17 a5 71 12 } //00 00 
	condition:
		any of ($a_*)
 
}