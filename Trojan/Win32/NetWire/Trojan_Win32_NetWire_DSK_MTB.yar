
rule Trojan_Win32_NetWire_DSK_MTB{
	meta:
		description = "Trojan:Win32/NetWire.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {81 c2 59 11 00 00 a1 90 01 04 8b ca a3 90 01 04 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}