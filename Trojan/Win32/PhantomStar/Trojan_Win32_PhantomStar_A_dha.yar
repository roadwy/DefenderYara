
rule Trojan_Win32_PhantomStar_A_dha{
	meta:
		description = "Trojan:Win32/PhantomStar.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {45 00 44 00 66 00 33 00 } //0a 00  EDf3
		$a_00_1 = {36 36 36 36 36 36 36 36 36 36 36 36 5c 5c 5c 5c 5c 5c } //0a 00  666666666666\\\\\\
		$a_00_2 = {4f 70 65 6e 53 53 4c 20 31 2e 30 2e 31 71 20 33 20 44 65 63 20 32 30 31 35 } //0a 00  OpenSSL 1.0.1q 3 Dec 2015
		$a_00_3 = {5b 73 79 73 74 65 6d 20 50 72 4f 63 45 73 73 5d } //01 00  [system PrOcEss]
		$a_01_4 = {63 6d 25 73 78 25 73 22 25 73 20 25 73 20 25 73 22 20 32 3e 25 } //01 00  cm%sx%s"%s %s %s" 2>%
		$a_01_5 = {70 69 6e 67 20 30 2e 30 2e 30 2e 30 3e 6e 75 6c } //01 00  ping 0.0.0.0>nul
		$a_01_6 = {69 66 20 65 78 69 73 74 20 25 25 31 20 67 6f 74 6f 20 50 } //01 00  if exist %%1 goto P
		$a_01_7 = {2f 41 55 54 4f 53 54 41 52 54 } //01 00  /AUTOSTART
		$a_00_8 = {49 45 4d 75 74 61 6e 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //01 00  IEMutantClassObject
		$a_00_9 = {73 65 61 72 63 68 69 6e 64 45 58 65 52 2e 65 58 65 } //01 00  searchindEXeR.eXe
		$a_00_10 = {6d 70 63 6d 64 72 75 6e 2e 65 78 65 } //01 00  mpcmdrun.exe
		$a_00_11 = {43 6f 6d 70 61 74 44 61 74 61 } //00 00  CompatData
	condition:
		any of ($a_*)
 
}