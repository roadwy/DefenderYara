
rule Trojan_Win32_Copak_GAN_MTB{
	meta:
		description = "Trojan:Win32/Copak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 d6 29 f6 e8 90 01 04 09 f2 31 39 81 ee 90 01 04 81 ee 90 01 04 81 ea 90 01 04 41 09 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}