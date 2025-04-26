
rule Trojan_Win32_ChirpingWater_A_dha{
	meta:
		description = "Trojan:Win32/ChirpingWater.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {c7 8d 0c 1f 99 47 f7 fe 8b 45 90 01 01 8a 04 02 8b 55 90 01 01 32 04 0a 88 01 8b 45 90 01 01 3b f8 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}