
rule Trojan_Win32_Injuke_RW_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 7e 00 00 00 89 45 90 01 01 6a 01 ff 15 90 01 04 89 45 90 01 01 6a 01 ff 15 90 01 04 89 45 90 01 01 b8 64 00 00 00 81 f0 cc fe a6 ac 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}