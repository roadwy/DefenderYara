
rule Worm_Win32_Ructo_H{
	meta:
		description = "Worm:Win32/Ructo.H,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 69 00 78 00 61 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  Baixa\Project1.vbp
		$a_01_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 2f 00 75 00 } //01 00  regsvr32 /s /u
		$a_01_2 = {40 00 74 00 65 00 72 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  @terra.com.br
		$a_01_3 = {4d 00 41 00 49 00 4c 00 20 00 46 00 52 00 4f 00 4d 00 3a 00 } //01 00  MAIL FROM:
		$a_01_4 = {5c 6d 73 6d 73 67 73 2e 65 78 65 } //00 00  \msmsgs.exe
	condition:
		any of ($a_*)
 
}