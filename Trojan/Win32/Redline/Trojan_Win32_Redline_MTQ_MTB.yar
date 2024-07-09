
rule Trojan_Win32_Redline_MTQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 0a 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 8b 45 ?? 0f be 14 10 6b d2 ?? 83 e2 ?? 83 e2 ?? 33 ca 88 4d ?? 0f be 45 ?? 0f be 4d ?? 03 c1 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}