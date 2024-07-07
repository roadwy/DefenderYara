
rule TrojanDownloader_O97M_Qakbot_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 20 2f 73 20 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 6c 6f 2e 6f 63 78 } //5 regsvr32 /s  C:\ProgramData\Plo.ocx
		$a_01_1 = {72 65 67 73 76 72 33 32 20 2f 73 20 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 6c 6f 31 2e 6f 63 78 } //5 regsvr32 /s  C:\ProgramData\Plo1.ocx
		$a_01_2 = {72 65 67 73 76 72 33 32 20 2f 73 20 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 6c 6f 32 2e 6f 63 78 } //5 regsvr32 /s  C:\ProgramData\Plo2.ocx
		$a_03_3 = {75 52 6c 4d 6f 6e 90 01 03 55 52 4c 44 20 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*1) >=6
 
}