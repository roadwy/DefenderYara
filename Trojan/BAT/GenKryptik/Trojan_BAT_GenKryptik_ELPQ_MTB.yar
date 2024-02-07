
rule Trojan_BAT_GenKryptik_ELPQ_MTB{
	meta:
		description = "Trojan:BAT/GenKryptik.ELPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 4a 53 44 4b 4c 44 48 53 44 } //01 00  NJSDKLDHSD
		$a_81_1 = {24 63 64 37 33 34 62 39 30 2d 32 66 37 30 2d 34 66 37 64 2d 38 34 62 63 2d 63 64 61 33 32 32 66 32 65 62 31 37 } //01 00  $cd734b90-2f70-4f7d-84bc-cda322f2eb17
		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_3 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_4 = {44 61 6f 56 61 6e 67 43 6c 69 65 6e 74 } //01 00  DaoVangClient
		$a_81_5 = {50 62 50 6c 61 79 65 72 4b 65 79 55 70 } //01 00  PbPlayerKeyUp
		$a_81_6 = {50 62 50 6c 61 79 65 72 4b 65 79 44 6f 77 6e } //01 00  PbPlayerKeyDown
		$a_81_7 = {67 72 61 31 2e 46 6f 72 6d 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //00 00  gra1.FormGame.resources
	condition:
		any of ($a_*)
 
}