
rule Trojan_Win32_Cosmu_AQ_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 65 67 61 6c 69 66 65 2e 62 65 73 74 68 6f 73 74 2e 62 79 2f 62 6f 74 2e 7a 69 70 } //1 megalife.besthost.by/bot.zip
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 73 79 73 63 6f 6e 66 2e 65 78 65 } //1 WINDOWS\Temp\sysconf.exe
		$a_01_2 = {49 20 77 69 6c 6c 20 73 75 65 20 79 6f 75 21 21 21 31 31 } //1 I will sue you!!!11
		$a_01_3 = {4c 6f 6f 6b 20 77 68 61 74 20 79 6f 75 20 64 69 64 20 74 6f 20 6d 79 20 63 6f 6d 70 75 74 65 72 21 21 21 21 } //1 Look what you did to my computer!!!!
		$a_01_4 = {53 75 73 61 6e 5f 6c 6f 76 65 78 78 40 } //1 Susan_lovexx@
		$a_01_5 = {43 3a 5c 6c 6f 67 2e 74 78 74 } //1 C:\log.txt
		$a_01_6 = {2a 2a 2a 42 45 4c 41 52 55 53 2d 56 49 52 55 53 2d 4d 41 4b 45 52 2a 2a 2a } //1 ***BELARUS-VIRUS-MAKER***
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}