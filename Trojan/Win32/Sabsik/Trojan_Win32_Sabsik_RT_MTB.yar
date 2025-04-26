
rule Trojan_Win32_Sabsik_RT_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 72 8b ?? ?? 99 f7 7d ?? 8b 45 ?? 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}