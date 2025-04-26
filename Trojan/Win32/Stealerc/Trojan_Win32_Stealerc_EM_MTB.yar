
rule Trojan_Win32_Stealerc_EM_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8a 42 0c 32 45 08 88 41 0c 5d e9 b6 00 00 00 55 8b ec 8a 42 19 32 45 08 88 41 19 5d e9 92 00 00 00 55 8b ec 8a 42 09 32 45 08 88 41 09 5d e9 6e 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}