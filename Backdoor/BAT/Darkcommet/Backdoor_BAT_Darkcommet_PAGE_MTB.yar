
rule Backdoor_BAT_Darkcommet_PAGE_MTB{
	meta:
		description = "Backdoor:BAT/Darkcommet.PAGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 00 6f 00 74 00 2f 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 70 00 68 00 70 00 } //2 bot/miner.php
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 SELECT Caption FROM Win32_OperatingSystem
		$a_01_2 = {5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 } //1 \root\SecurityCenter
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 64 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //2 SELECT displayName FROM AntivirusProduct
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}