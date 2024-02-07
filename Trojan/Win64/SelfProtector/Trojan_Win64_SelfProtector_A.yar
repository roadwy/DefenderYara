
rule Trojan_Win64_SelfProtector_A{
	meta:
		description = "Trojan:Win64/SelfProtector.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 14 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //0a 00  winhost.exe
		$a_01_1 = {6e 00 68 00 65 00 71 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //05 00  nheqminer.exe
		$a_01_2 = {54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 } //05 00  TMethodImplementationIntercept
		$a_01_3 = {48 00 6f 00 6f 00 6b 00 65 00 64 00 20 00 41 00 50 00 49 00 73 00 } //0a 00  Hooked APIs
		$a_01_4 = {48 89 f3 8b 03 48 8d 34 03 48 8b 4e 40 48 8d 15 42 00 00 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}