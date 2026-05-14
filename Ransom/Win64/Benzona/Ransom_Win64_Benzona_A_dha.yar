
rule Ransom_Win64_Benzona_A_dha{
	meta:
		description = "Ransom:Win64/Benzona.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 45 43 4f 56 45 52 59 5f 49 4e 46 4f 2e 74 78 74 } //1 RECOVERY_INFO.txt
		$a_01_1 = {77 61 6c 6c 70 61 70 65 72 2e 70 6e 67 } //1 wallpaper.png
		$a_01_2 = {2e 62 65 6e 7a 6f 6e 61 } //1 .benzona
		$a_01_3 = {52 53 41 20 65 6e 63 72 79 70 74 69 6f 6e 20 66 61 69 6c 65 64 } //1 RSA encryption failed
		$a_01_4 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //1 wbadmin delete catalog -quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}