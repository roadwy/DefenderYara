
rule Backdoor_Win32_Bazarldr_AD_MTB{
	meta:
		description = "Backdoor:Win32/Bazarldr.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 08 0f b6 55 ?? 33 ca a1 ?? ?? ?? ?? 03 45 ?? 88 08 e9 90 09 13 00 41 8a 89 ?? ?? ?? ?? 88 4d ?? a1 ?? ?? ?? ?? 03 45 ?? 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}