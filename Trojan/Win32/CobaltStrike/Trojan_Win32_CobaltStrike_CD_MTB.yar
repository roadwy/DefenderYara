
rule Trojan_Win32_CobaltStrike_CD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 03 55 ?? 0f be 0a 03 4d ?? 8b 45 ?? 33 d2 be ?? ?? ?? ?? f7 f6 03 ca 8b c1 33 d2 b9 ?? ?? ?? ?? f7 f1 89 55 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}