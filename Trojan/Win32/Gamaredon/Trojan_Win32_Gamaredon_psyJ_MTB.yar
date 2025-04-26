
rule Trojan_Win32_Gamaredon_psyJ_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 48 08 83 c1 01 8b 95 88 fb ff ff 89 4a 08 ff 15 14 20 40 00 89 85 80 fb ff ff 8b 85 80 fb ff ff 50 68 dc 20 40 00 8d 4d ac 51 ff 15 44 20 40 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}