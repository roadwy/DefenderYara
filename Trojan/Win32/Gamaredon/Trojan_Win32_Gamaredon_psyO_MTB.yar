
rule Trojan_Win32_Gamaredon_psyO_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 f7 74 2d 8a d3 8d 4c 24 10 80 c2 41 52 e8 d8 00 00 00 68 2c 41 40 00 8d 4c 24 14 e8 88 00 00 00 8d 4c 24 0c 8b 44 24 10 50 6a 00 e8 86 fc ff ff 03 f6 43 83 fb 1a 7c c7 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}