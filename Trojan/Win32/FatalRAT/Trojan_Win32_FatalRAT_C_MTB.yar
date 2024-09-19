
rule Trojan_Win32_FatalRAT_C_MTB{
	meta:
		description = "Trojan:Win32/FatalRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff ?? ?? 14 54 00 8b f0 83 fe ff 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 08 8b f0 6a 0a 8b ce e8 ?? ?? 00 00 8b 06 8b 40 04 eb ?? 8b 03 8b 4b 04 6a 00 8d 55 fc 52 2b c8 51 50 56 ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}