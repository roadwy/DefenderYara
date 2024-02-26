
rule Trojan_Win32_NetLoader_AW_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {be e6 81 db 06 4e 5e 9d 32 06 60 fd 89 c6 57 59 fc 61 88 07 } //00 00 
	condition:
		any of ($a_*)
 
}