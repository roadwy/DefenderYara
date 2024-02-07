
rule Trojan_Win64_BumbleBee_AM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 65 69 31 35 69 } //02 00  Eei15i
		$a_01_1 = {4c 69 52 4e 4e 35 46 } //02 00  LiRNN5F
		$a_01_2 = {58 5a 72 45 58 39 32 32 36 31 } //02 00  XZrEX92261
		$a_01_3 = {64 6f 6c 6c 73 20 74 68 65 6d 20 73 63 69 65 6e 74 69 66 69 63 } //00 00  dolls them scientific
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_AM_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 61 6d 70 20 66 61 72 72 69 65 72 } //03 00  damp farrier
		$a_01_1 = {63 75 72 6c 20 73 74 65 72 6e } //02 00  curl stern
		$a_01_2 = {6a 61 7a 7a 20 6e 61 70 6f 6c 65 6f 6e } //02 00  jazz napoleon
		$a_01_3 = {6a 70 48 67 45 63 74 4f 4f 50 } //00 00  jpHgEctOOP
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_AM_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 57 48 77 79 36 52 } //02 00  RWHwy6R
		$a_01_1 = {6c 46 4a 55 4e 6b 78 47 68 4c } //02 00  lFJUNkxGhL
		$a_01_2 = {53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //02 00  SetCurrentDirectoryA
		$a_01_3 = {75 67 67 79 20 72 65 63 6f 76 65 72 20 70 6f 6c 69 74 65 6e 65 73 73 } //00 00  uggy recover politeness
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_AM_MTB_4{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 53 65 74 50 72 6f 78 79 42 6c 61 6e 6b 65 74 } //01 00  CoSetProxyBlanket
		$a_01_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 50 72 6f 64 75 63 74 } //01 00  SELECT * FROM Win32_ComputerSystemProduct
		$a_01_2 = {4c 64 72 41 64 64 78 36 34 2e 65 78 65 } //01 00  LdrAddx64.exe
		$a_01_3 = {50 72 6f 63 65 73 73 4c 6f 61 64 } //01 00  ProcessLoad
		$a_01_4 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 6d 79 5f 61 70 70 6c 69 63 61 74 69 6f 6e 5f 70 61 74 68 22 } //01 00  objShell.Run "my_application_path"
		$a_01_5 = {57 69 6e 64 6f 77 73 20 50 68 6f 74 6f 20 56 69 65 77 65 72 5c 49 6d 61 67 69 6e 67 44 65 76 69 63 65 73 2e 65 78 65 } //01 00  Windows Photo Viewer\ImagingDevices.exe
		$a_01_6 = {57 69 6e 64 6f 77 73 20 4d 61 69 6c 5c 77 61 62 2e 65 78 65 } //01 00  Windows Mail\wab.exe
		$a_01_7 = {5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 } //00 00  Z:\hooker2
	condition:
		any of ($a_*)
 
}