
rule Trojan_Win32_Zenpak_SPAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 ec 08 8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 55 fa 0f b6 75 fb 31 f2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}