
rule Trojan_Win32_DelfInject_RRR_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 47 02 00 00 a9 1c 00 00 00 0f af cb 6a 04 68 00 10 00 00 a1 90 01 04 50 8b 06 8d 04 80 8b 15 90 01 04 8b 44 c2 90 01 01 03 05 90 01 04 50 e8 90 01 04 a3 90 01 04 69 c0 47 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}