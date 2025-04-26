
rule PWS_Win32_Zbot_MR_MTB{
	meta:
		description = "PWS:Win32/Zbot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4f 52 8b 17 4e 8b 06 33 c2 5a 47 c1 e8 ?? 4a 46 46 52 aa 58 85 c0 75 ?? 8b 45 ?? 8b 55 ?? 8b f0 e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}