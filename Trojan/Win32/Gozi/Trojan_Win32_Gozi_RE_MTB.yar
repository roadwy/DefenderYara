
rule Trojan_Win32_Gozi_RE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 fc 0f b6 08 8b 45 fc 99 be 34 00 00 00 f7 fe 8b 45 f4 0f b6 14 10 33 ca 8b 45 f8 03 45 fc 88 08 eb c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b 8d 80 ee ff ff 40 0f af 85 6c ee ff ff 03 c6 03 05 ?? ?? ?? ?? 99 f7 bd 74 ee ff ff 8b 85 78 ee ff ff 30 14 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0b 2b 4d 0c 89 45 f8 8b c2 c1 f8 1f 83 c8 ff 2b 45 0c 83 c7 04 83 c3 04 [0-08] 3b c8 76 09 c7 45 0c 01 00 00 00 eb 04 83 65 0c 00 8b 4d f8 29 0e 8b 06 83 ca ff 2b d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}