
rule Trojan_Win32_Zusy_RC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 48 3e 00 00 50 b8 cb 6d 00 00 b8 2f 18 00 00 58 58 52 ba da 16 00 00 51 b9 55 78 00 00 b9 0f 22 00 00 59 5a 52 52 ba 79 18 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}