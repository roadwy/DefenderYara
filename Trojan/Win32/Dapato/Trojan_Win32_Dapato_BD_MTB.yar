
rule Trojan_Win32_Dapato_BD_MTB{
	meta:
		description = "Trojan:Win32/Dapato.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 a5 1b f5 32 24 00 00 94 08 00 f0 00 a2 f3 1d 1b f5 33 24 00 00 94 08 00 f0 00 a2 f3 9d 1b f5 34 24 00 00 94 08 00 f0 00 a2 f3 f9 1a f5 35 24 00 00 94 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}