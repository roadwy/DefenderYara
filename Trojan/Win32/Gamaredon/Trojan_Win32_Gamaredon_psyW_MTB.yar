
rule Trojan_Win32_Gamaredon_psyW_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {31 13 90 90 90 90 90 90 90 83 c3 04 90 39 cb 90 90 90 90 7c eb } //00 00 
	condition:
		any of ($a_*)
 
}