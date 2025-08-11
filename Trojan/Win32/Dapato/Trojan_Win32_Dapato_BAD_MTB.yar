
rule Trojan_Win32_Dapato_BAD_MTB{
	meta:
		description = "Trojan:Win32/Dapato.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fe 81 ef ?? ?? ?? ?? 2b f8 31 3b 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}