
rule Ransom_Win32_VirLock_RPX_MTB{
	meta:
		description = "Ransom:Win32/VirLock.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 42 90 46 90 e9 00 00 00 00 47 90 49 } //00 00 
	condition:
		any of ($a_*)
 
}