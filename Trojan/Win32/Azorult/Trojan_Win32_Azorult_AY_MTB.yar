
rule Trojan_Win32_Azorult_AY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 90 90 05 10 01 90 8b 7d fc ff 75 f8 01 3c 24 c3 } //1
		$a_02_1 = {8b d0 32 8e ?? ?? ?? 00 88 0a 90 05 10 01 90 5e c3 90 0a 30 00 56 90 05 10 01 90 8b f2 90 05 10 01 (05 10 01 90 8b d0 |)} //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}