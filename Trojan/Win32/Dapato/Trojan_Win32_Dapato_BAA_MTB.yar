
rule Trojan_Win32_Dapato_BAA_MTB{
	meta:
		description = "Trojan:Win32/Dapato.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fe 81 ef ?? ?? ?? ?? 03 c7 31 03 83 45 ec 04 6a 00 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}