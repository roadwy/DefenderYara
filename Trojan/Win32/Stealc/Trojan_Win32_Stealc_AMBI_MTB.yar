
rule Trojan_Win32_Stealc_AMBI_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 75 e0 8b 45 ec 31 45 fc 33 75 fc 89 75 dc 8b 45 dc } //00 00 
	condition:
		any of ($a_*)
 
}