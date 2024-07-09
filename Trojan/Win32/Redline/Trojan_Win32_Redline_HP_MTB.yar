
rule Trojan_Win32_Redline_HP_MTB{
	meta:
		description = "Trojan:Win32/Redline.HP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d1 83 f1 ?? 83 f1 ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}