
rule Trojan_Win32_RedLine_RDCQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 04 3e 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e } //00 00 
	condition:
		any of ($a_*)
 
}