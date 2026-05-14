
rule Trojan_BAT_Crysan_MKB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 34 00 00 0a 0b 07 73 2b 00 00 0a 0c 08 72 b9 01 00 70 6f 2c 00 00 0a 08 72 cf 01 00 70 6f 30 00 00 0a 08 17 6f 2e 00 00 0a 08 17 6f 3b 00 00 0a 08 6f 39 00 00 0a } //20
		$a_81_1 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 65 78 65 2c 62 61 74 2c 64 6c 6c 2c 70 73 31 3b 65 78 69 74 } //10 Set-MpPreference -ExclusionExtension exe,bat,dll,ps1;exit
		$a_81_2 = {2f 41 73 41 64 6d 69 6e 22 20 2f 53 54 20 30 30 3a 30 31 20 2f 49 54 20 2f 46 20 2f 52 4c 20 48 49 47 48 45 53 54 } //5 /AsAdmin" /ST 00:01 /IT /F /RL HIGHEST
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}