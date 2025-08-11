
rule Trojan_Win32_Amadey_NJL_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {4c 55 4e 57 48 30 55 72 68 6d 32 74 4c 36 68 79 58 7a 57 34 51 65 79 71 39 71 3d 3d } //2 LUNWH0Urhm2tL6hyXzW4Qeyq9q==
		$a_81_1 = {77 68 45 67 46 54 66 57 55 6c 62 37 52 34 47 77 46 67 4f 20 56 69 56 77 4f 69 49 77 3d 3d } //1 whEgFTfWUlb7R4GwFgO ViVwOiIw==
		$a_81_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 72 75 6c 65 20 67 72 6f 75 70 3d 22 52 65 6d 6f 74 65 20 44 65 73 6b 74 6f 70 22 20 6e 65 77 20 65 6e 61 62 6c 65 3d 59 65 73 } //1 netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
		$a_81_3 = {53 45 54 20 50 61 73 73 77 6f 72 64 63 68 61 6e 67 65 61 62 6c 65 3d 46 41 4c 53 45 } //1 SET Passwordchangeable=FALSE
		$a_81_4 = {57 4d 49 43 20 55 53 45 52 41 43 43 4f 55 4e 54 20 57 48 45 52 45 20 22 4e 61 6d 65 20 3d } //1 WMIC USERACCOUNT WHERE "Name =
		$a_81_5 = {4d 71 55 72 51 45 63 54 33 57 71 54 5a 30 4a 35 61 66 6d 30 6a 48 3d 3d } //1 MqUrQEcT3WqTZ0J5afm0jH==
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}