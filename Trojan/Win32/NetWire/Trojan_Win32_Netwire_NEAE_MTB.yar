
rule Trojan_Win32_Netwire_NEAE_MTB{
	meta:
		description = "Trojan:Win32/Netwire.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7d 34 40 0f b6 c0 8a 4c 04 10 01 ce 89 f2 0f b6 f2 0f b6 6c 34 10 89 ea 88 54 04 10 8b 54 24 0c 88 4c 34 10 01 e9 0f b6 c9 8a 4c 0c 10 30 0c 17 ff 44 24 0c eb c6 } //00 00 
	condition:
		any of ($a_*)
 
}