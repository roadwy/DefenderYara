
rule Trojan_Win32_Stealerc_PAFL_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.PAFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 30 0c 38 47 3b fb 7c e6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}