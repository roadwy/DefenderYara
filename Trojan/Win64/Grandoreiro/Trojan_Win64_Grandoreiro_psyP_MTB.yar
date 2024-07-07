
rule Trojan_Win64_Grandoreiro_psyP_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 9b 09 00 00 33 c9 e8 f7 a1 fc ff 48 8b c8 e8 03 8c fc ff 48 8d 15 7c 21 04 00 49 8b 0c 24 e8 fb 97 fc ff 48 8b f8 41 bd 02 00 00 00 45 8b c5 33 d2 48 8b c8 e8 59 9e fc ff 48 8b cf e8 45 96 fc ff 48 63 d8 89 5c 24 50 45 33 c0 33 d2 48 8b cf e8 3d 9e fc ff 48 8b cb e8 61 3a fc ff 48 8b f0 48 89 44 24 78 4c 8b cf 4c 8b c3 49 8b d6 48 8b c8 e8 5c a4 fc ff 48 8b cf e8 a0 9b fc ff 8b 4c 33 f8 8b 54 33 fc 89 54 24 70 ff c9 89 4c 24 74 33 db 8b f3 85 d2 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}