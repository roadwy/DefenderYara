
rule Backdoor_Win32_Coroxy_CA_MTB{
	meta:
		description = "Backdoor:Win32/Coroxy.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 8b 55 10 88 02 8a 07 30 02 ff 45 10 eb } //00 00 
	condition:
		any of ($a_*)
 
}