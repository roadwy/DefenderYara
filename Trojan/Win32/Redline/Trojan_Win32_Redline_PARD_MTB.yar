
rule Trojan_Win32_Redline_PARD_MTB{
	meta:
		description = "Trojan:Win32/Redline.PARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be bc 15 ?? ?? ?? ?? 99 f7 ff 0f af 45 ?? 2b f0 0f b6 44 35 ?? 33 c8 8b 55 ?? 03 55 ?? 88 0a eb } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}