
rule Trojan_Win32_Shellcode_EART_MTB{
	meta:
		description = "Trojan:Win32/Shellcode.EART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 33 d6 2b fa 81 c3 ?? ?? ?? ?? 83 6d ec 01 89 7d f0 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}