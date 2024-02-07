
rule Trojan_Win64_CryptInject_LSG_MSR{
	meta:
		description = "Trojan:Win64/CryptInject.LSG!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 6c 77 61 72 65 5a 6f 6f } //01 00  MalwareZoo
		$a_01_1 = {4c 6f 63 61 6c 5c 7b 43 31 35 37 33 30 45 32 2d 31 34 35 43 2d 34 63 35 65 2d 42 30 30 35 2d 33 42 43 37 35 33 46 34 32 34 37 35 7d 2d 6f 6e 63 65 2d 66 6c 61 67 } //01 00  Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag
		$a_01_2 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 20 79 6f 75 20 68 61 76 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 6d 61 6e 75 61 6c 6c 79 20 69 6e 6a 65 63 74 65 64 20 61 20 44 4c 4c } //01 00  Congratulations you have successfully manually injected a DLL
		$a_01_3 = {42 4f 4f 4d } //01 00  BOOM
		$a_01_4 = {52 65 66 6c 65 63 74 69 76 65 49 6e 6a 65 63 74 69 6f 6e } //00 00  ReflectiveInjection
	condition:
		any of ($a_*)
 
}