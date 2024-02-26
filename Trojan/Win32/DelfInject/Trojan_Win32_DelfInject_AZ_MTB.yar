
rule Trojan_Win32_DelfInject_AZ_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 cc 8a 04 33 } //01 00 
		$a_01_1 = {32 07 88 07 47 4b } //00 00 
	condition:
		any of ($a_*)
 
}