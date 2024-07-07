
rule Trojan_Win32_Guildma_psyV_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 75 f0 ff d7 8b 5d e4 8d 4c 00 02 8b 45 ec 03 c3 3b ce 76 13 8b 55 f0 2b d0 89 4d f4 8a 0c 02 88 08 40 ff 4d f4 75 f5 56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 fc ff 15 38 20 40 00 89 45 f4 83 f8 ff 0f 84 55 ff ff ff 56 8d 45 e8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}