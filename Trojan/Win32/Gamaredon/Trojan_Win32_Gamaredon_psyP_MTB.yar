
rule Trojan_Win32_Gamaredon_psyP_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 41 84 c0 75 f9 2b ca 8b 55 fc 8b f1 2b d6 4a 83 cb ff 33 ff 89 5d fc 85 d2 7e 27 33 c9 85 f6 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}