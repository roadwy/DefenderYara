
rule Trojan_Win64_ReverseShell_KKA_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 10 89 c1 83 e1 07 8a 54 0c 18 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 01 c1 32 11 88 11 48 83 c0 01 48 83 f8 1c 48 89 44 24 10 } //20
		$a_01_1 = {5b 45 52 52 4f 52 5d 20 57 53 41 53 74 75 72 74 75 70 20 66 61 69 6c 65 64 2e } //10 [ERROR] WSASturtup failed.
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}