
rule Trojan_Win32_Rm3_A_MTB{
	meta:
		description = "Trojan:Win32/Rm3.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 03 cf 0f b7 c9 0f af c8 66 03 cf 0f b7 c9 0f af c8 66 03 cf 0f b7 c1 } //00 00 
	condition:
		any of ($a_*)
 
}