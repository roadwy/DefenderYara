
rule Trojan_Win64_ReverseShell_KK_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 ac 24 88 00 00 00 48 8d ac 24 88 00 00 00 48 8b ?? ?? 1b 29 00 48 8b ?? ?? 1b 29 00 48 85 d2 } //20
		$a_01_1 = {48 89 5c 24 50 48 89 44 24 38 48 8b 48 18 48 89 d8 ff d1 48 85 db 0f 95 c1 48 8b 44 24 38 48 8b 5c 24 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_ReverseShell_KK_MTB_2{
	meta:
		description = "Trojan:Win64/ReverseShell.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 bc 00 00 00 89 84 24 84 00 00 00 65 48 8b 04 25 ?? 00 00 00 48 8b 40 18 48 89 c1 48 83 c1 10 48 89 8c 24 88 00 00 00 48 8b 40 10 48 39 c8 48 89 84 24 90 90 00 00 00 } //20
		$a_01_1 = {5b 45 52 52 4f 52 5d 20 57 53 41 53 74 75 72 74 75 70 20 66 61 69 6c 65 64 2e } //10 [ERROR] WSASturtup failed.
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}