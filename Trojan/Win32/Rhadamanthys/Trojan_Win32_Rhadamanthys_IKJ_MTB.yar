
rule Trojan_Win32_Rhadamanthys_IKJ_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.IKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 51 03 c5 50 8d 54 24 ?? 52 89 4c 24 ?? e8 ?? ?? ?? ?? 2b 74 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 89 74 24 ?? 0f 85 90 0a 42 00 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}