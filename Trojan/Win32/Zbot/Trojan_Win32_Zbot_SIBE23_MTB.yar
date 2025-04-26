
rule Trojan_Win32_Zbot_SIBE23_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE23!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 f8 89 c7 89 44 24 ?? be ?? ?? ?? ?? 01 c6 80 38 00 75 ?? 8a 0a 88 08 42 40 39 c6 75 ?? 90 18 5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 ?? 31 c9 83 ea ?? 47 39 f8 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}