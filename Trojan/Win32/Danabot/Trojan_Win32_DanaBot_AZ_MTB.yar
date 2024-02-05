
rule Trojan_Win32_DanaBot_AZ_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 ce 30 01 b8 90 02 30 83 f0 90 01 01 83 ad 90 02 30 39 bd 90 02 20 90 13 90 02 20 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}