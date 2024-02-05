
rule Trojan_Win32_AveMariaRat_MB_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ac 24 18 04 00 00 41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 7c 8c 14 03 f7 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 5c 8c 14 8b 7c b4 14 88 5c 24 10 89 7c 8c 14 8b 7c 24 10 81 e7 ff 00 00 00 89 7c b4 14 8b 5c 8c 14 03 df 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 72 } //01 00 
		$a_01_1 = {8b f8 85 f6 89 7d 0c 76 19 8b 45 08 8b cf 2b c7 89 75 08 8a 14 08 88 11 8b 55 08 41 4a 89 55 08 75 } //00 00 
	condition:
		any of ($a_*)
 
}