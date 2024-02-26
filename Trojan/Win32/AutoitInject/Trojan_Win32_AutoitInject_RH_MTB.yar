
rule Trojan_Win32_AutoitInject_RH_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 95 70 1c f1 48 6d fa ab 82 0c dd e4 31 68 46 bc 77 a1 09 af d8 d0 85 05 fa 8d 48 b5 77 09 85 } //01 00 
		$a_01_1 = {fd 71 bc c3 f2 48 c7 9e e8 f2 f8 8d b0 f5 3e f6 5b f0 ed 42 9b f2 7e 1a be 26 aa 35 84 e6 ec 80 } //00 00 
	condition:
		any of ($a_*)
 
}