
rule Trojan_Win32_Glupteba_MS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 4d dc 51 ff 15 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 33 c6 8b 75 ?? 2b f8 8b cf c1 e1 ?? 03 4d ?? 8b c7 c1 e8 ?? 03 45 ?? 03 f7 33 ce 33 c8 c7 05 [0-08] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 2b d9 8b 45 ?? 29 45 [0-05] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}