
rule Trojan_Win64_Sanny_A{
	meta:
		description = "Trojan:Win64/Sanny.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 62 56 49 6e 3d 42 55 2f 64 71 4e 50 32 6b 57 77 30 6f 43 72 6d 39 78 61 4a 33 74 5a 58 36 4f 70 46 63 37 41 73 69 34 6c 76 75 68 66 2d 54 6a 4d 4c 52 51 35 47 4b 65 45 48 59 67 44 31 79 7a 38 } //1 SbVIn=BU/dqNP2kWw0oCrm9xaJ3tZX6OpFc7Asi4lvuhf-TjMLRQ5GKeEHYgD1yz8
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 63 6c 69 63 6f 6e 66 67 2e 65 78 65 20 2f 66 } //1 taskkill /im cliconfg.exe /f
		$a_01_2 = {64 65 6c 20 2f 66 20 2f 71 20 4e 54 57 44 42 4c 49 42 2e 44 4c 4c } //1 del /f /q NTWDBLIB.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}