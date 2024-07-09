
rule DDoS_Linux_Xarcen_A_MTB{
	meta:
		description = "DDoS:Linux/Xarcen.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 04 8d 85 e9 df ff ff 89 04 24 e8 27 f5 ff ff 8d 85 e9 df ff ff 89 74 24 0c c7 44 24 08 ?? ?? 0b 08 c7 44 24 04 00 10 00 00 89 04 24 e8 ?? ?? ?? 00 8d 85 e9 cf ff ff 89 04 24 e8 ?? ?? ?? 00 89 44 24 08 8d 85 e9 cf ff ff 89 44 24 04 8d 85 e9 df ff ff 89 04 24 e8 db f4 ff ff 8b 45 08 } //1
		$a_01_1 = {2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 25 73 2e 73 68 } //1 /etc/cron.hourly/%s.sh
		$a_01_2 = {64 65 6e 79 69 70 3d } //1 denyip=
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}