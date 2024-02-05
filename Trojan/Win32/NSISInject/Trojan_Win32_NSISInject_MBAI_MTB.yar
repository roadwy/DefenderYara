
rule Trojan_Win32_NSISInject_MBAI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 90 01 04 30 04 1e 46 3b f7 72 de 90 00 } //01 00 
		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 57 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}