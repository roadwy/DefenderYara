
rule Trojan_BAT_AgentTesla_RTC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 65 6c 70 68 69 2d 74 68 65 20 62 65 73 74 2e 20 46 75 63 6b 20 6f 66 66 20 61 6c 6c 20 74 68 65 20 72 65 73 74 } //Delphi-the best. Fuck off all the rest  1
		$a_80_1 = {52 6d 4a 33 37 4b 37 6a 4e 67 64 41 64 73 34 4f 68 5a 2e 65 6a 66 57 70 44 35 5a 45 69 50 54 4f 70 4a 62 52 43 } //RmJ37K7jNgdAds4OhZ.ejfWpD5ZEiPTOpJbRC  1
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  1
		$a_80_3 = {39 31 2e 32 34 33 2e 34 34 2e 32 32 } //91.243.44.22  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}