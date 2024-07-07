
rule Trojan_Win32_Qakbot_MSD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 28 83 c5 04 8b 43 7c 31 43 48 8b c1 2b 43 78 35 90 01 04 0f af 43 10 89 43 10 33 c0 40 2b c1 01 83 90 01 04 8b 43 2c 8b 53 60 35 90 01 04 0f af 43 2c 0f af d6 89 43 2c 8b 4b 68 8b 83 90 01 04 88 14 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}