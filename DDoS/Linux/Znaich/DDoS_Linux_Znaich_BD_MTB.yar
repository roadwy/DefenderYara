
rule DDoS_Linux_Znaich_BD_MTB{
	meta:
		description = "DDoS:Linux/Znaich.BD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 54 24 0c 89 54 24 08 c7 44 24 90 01 05 89 04 24 e8 90 01 04 8d 95 e8 fa ff ff 89 14 24 90 00 } //01 00 
		$a_03_1 = {89 74 24 0c 83 c6 01 89 7c 24 10 c7 44 24 90 01 05 c7 44 24 04 00 04 00 00 89 1c 24 e8 90 01 04 89 1c 24 e8 90 01 04 89 1c 24 e8 90 00 } //01 00 
		$a_03_2 = {8b 45 0c 89 74 24 18 89 74 24 14 89 74 24 10 89 44 24 0c 8d 85 e3 fe ff ff 89 44 24 08 c7 44 24 90 01 05 89 1c 24 e8 90 01 04 89 1c 24 90 00 } //01 00 
		$a_03_3 = {89 54 24 10 89 3c 24 89 5c 24 0c c7 44 24 90 01 05 c7 44 24 90 01 05 e8 90 01 04 89 3c 24 e8 90 01 04 c7 04 24 02 00 00 00 e8 90 01 04 8b 85 e0 ea ff ff 90 00 } //01 00 
		$a_00_4 = {43 4f 4d 4d 41 4e 44 5f 44 44 4f 53 5f 53 54 4f 50 } //01 00  COMMAND_DDOS_STOP
		$a_00_5 = {73 65 64 20 2d 69 20 27 2f 5c 2f 65 74 63 5c 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 5c 2f 63 72 6f 6e 2e 73 68 2f 64 27 20 2f 65 74 63 2f 63 72 6f 6e 74 61 62 } //00 00  sed -i '/\/etc\/cron.hourly\/cron.sh/d' /etc/crontab
	condition:
		any of ($a_*)
 
}