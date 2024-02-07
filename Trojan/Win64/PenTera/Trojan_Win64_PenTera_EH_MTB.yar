
rule Trojan_Win64_PenTera_EH_MTB{
	meta:
		description = "Trojan:Win64/PenTera.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6d 6f 74 65 52 75 6e 6e 65 72 41 50 43 } //01 00  RemoteRunnerAPC
		$a_01_1 = {43 72 79 70 74 41 63 71 48 } //01 00  CryptAcqH
		$a_01_2 = {75 69 72 65 43 6f 6e 74 48 } //01 00  uireContH
		$a_01_3 = {2f 63 20 70 69 6e 67 20 2d 6e 20 32 30 20 31 32 37 2e 30 2e 30 2e 31 20 3e 20 6e 75 6c 20 26 20 64 65 6c } //00 00  /c ping -n 20 127.0.0.1 > nul & del
	condition:
		any of ($a_*)
 
}