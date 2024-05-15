
rule Trojan_Win32_RisePro_RP_MTB{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } //01 00  Software\WinLicense
		$a_01_1 = {53 74 65 61 6c 65 72 43 6c 69 65 6e 74 } //00 00  StealerClient
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RisePro_RP_MTB_2{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } //01 00  Software\WinLicense
		$a_01_1 = {5c 5c 2e 5c 53 49 57 56 49 44 } //01 00  \\.\SIWVID
		$a_01_2 = {6f 72 65 61 6e 73 33 32 2e 73 79 73 } //01 00  oreans32.sys
		$a_01_3 = {6f 72 65 61 6e 73 78 36 34 2e 73 79 73 } //01 00  oreansx64.sys
		$a_01_4 = {48 41 52 44 57 41 52 45 5c 41 43 50 49 5c 44 53 44 54 5c 56 42 4f 58 5f 5f } //01 00  HARDWARE\ACPI\DSDT\VBOX__
		$a_01_5 = {68 00 65 00 69 00 64 00 69 00 73 00 71 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  heidisql.exe
		$a_01_6 = {41 00 6e 00 73 00 67 00 61 00 72 00 20 00 42 00 65 00 63 00 6b 00 65 00 72 00 2c 00 20 00 73 00 65 00 65 00 20 00 67 00 70 00 6c 00 2e 00 74 00 78 00 74 00 } //00 00  Ansgar Becker, see gpl.txt
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RisePro_RP_MTB_3{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 74 61 67 67 61 6e 74 00 30 00 00 00 90 01 04 22 00 00 90 00 } //01 00 
		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 78 36 34 } //01 00  \\.\Global\oreansx64
		$a_01_2 = {50 6c 65 61 73 65 2c 20 63 6f 6e 74 61 63 74 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 64 65 76 65 6c 6f 70 65 72 73 20 77 69 74 68 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 63 6f 64 65 73 2e 20 54 68 61 6e 6b 20 79 6f 75 2e } //01 00  Please, contact the software developers with the following codes. Thank you.
		$a_01_3 = {50 6c 65 61 73 65 2c 20 63 6f 6e 74 61 63 74 20 79 6f 75 72 73 69 74 65 40 79 6f 75 72 73 69 74 65 2e 63 6f 6d 2e 20 54 68 61 6e 6b 20 79 6f 75 21 } //01 00  Please, contact yoursite@yoursite.com. Thank you!
		$a_01_4 = {04 64 a0 59 40 05 ce 0a 40 05 ce 0a 40 05 ce 0a 1b 6d cd 0b 51 05 ce 0a 1b 6d cb 0b e0 05 ce 0a 95 68 ca 0b 52 05 ce 0a 95 68 cd 0b 57 05 ce 0a 95 68 cb 0b 35 05 ce 0a 1b 6d ca 0b 55 05 ce 0a 1b 6d cf 0b 53 05 ce 0a 40 05 cf 0a 94 05 ce 0a db 6b c7 0b 41 05 ce 0a db 6b 31 0a 41 05 ce 0a db 6b cc 0b 41 05 ce 0a 52 69 63 68 40 05 ce 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RisePro_RP_MTB_4{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 4c 4e 75 6d 44 4c 4c 73 50 72 6f 74 } //01 00  WLNumDLLsProt
		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 78 36 34 } //01 00  \\.\Global\oreansx64
		$a_01_2 = {58 70 72 6f 74 45 76 65 6e 74 } //01 00  XprotEvent
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } //01 00  Software\WinLicense
		$a_01_4 = {52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //0a 00  RestartApp.exe
		$a_01_5 = {2a 52 e4 13 6e 33 8a 40 6e 33 8a 40 6e 33 8a 40 35 5b 89 41 60 33 8a 40 35 5b 8f 41 f0 33 8a 40 bb 5e 8e 41 7c 33 8a 40 bb 5e 89 41 7a 33 8a 40 bb 5e 8f 41 1b 33 8a 40 35 5b 8e 41 7a 33 8a 40 35 5b 8b 41 7d 33 8a 40 6e 33 8b 40 ba 33 8a 40 f5 5d 83 41 6f 33 8a 40 f5 5d 75 40 6f 33 8a 40 f5 5d 88 41 6f 33 8a 40 52 69 63 68 6e 33 8a 40 } //0a 00 
		$a_01_6 = {04 64 a0 59 40 05 ce 0a 40 05 ce 0a 40 05 ce 0a 1b 6d cd 0b 51 05 ce 0a 1b 6d cb 0b e0 05 ce 0a 95 68 ca 0b 52 05 ce 0a 95 68 cd 0b 57 05 ce 0a 95 68 cb 0b 35 05 ce 0a 1b 6d ca 0b 55 05 ce 0a 1b 6d cf 0b 53 05 ce 0a 40 05 cf 0a 94 05 ce 0a db 6b c7 0b 41 05 ce 0a db 6b 31 0a 41 05 ce 0a db 6b cc 0b 41 05 ce 0a 52 69 63 68 40 05 ce 0a } //0a 00 
		$a_01_7 = {6a 99 1d e4 2e f8 73 b7 2e f8 73 b7 2e f8 73 b7 65 80 70 b6 25 f8 73 b7 65 80 76 b6 ee f8 73 b7 65 80 74 b6 2f f8 73 b7 ec 79 8e b7 2a f8 73 b7 ec 79 77 b6 3d f8 73 b7 ec 79 70 b6 34 f8 73 b7 ec 79 76 b6 75 f8 73 b7 65 80 77 b6 36 f8 73 b7 65 80 75 b6 2f f8 73 b7 65 80 72 b6 35 f8 73 b7 2e f8 72 b7 0e f9 73 b7 dd 7a 7a b6 32 f8 73 b7 dd 7a 8c b7 2f f8 73 b7 2e f8 e4 b7 2f f8 73 b7 dd 7a 71 b6 2f f8 73 b7 52 69 63 68 2e f8 73 b7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RisePro_RP_MTB_5{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 0c 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 4c 4e 75 6d 44 4c 4c 73 50 72 6f 74 } //05 00  WLNumDLLsProt
		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 78 36 34 } //05 00  \\.\Global\oreansx64
		$a_01_2 = {58 70 72 6f 74 45 76 65 6e 74 } //05 00  XprotEvent
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } //0a 00  Software\WinLicense
		$a_01_4 = {a4 6b 87 80 e0 0a e9 d3 e0 0a e9 d3 e0 0a e9 d3 ab 72 ea d2 eb 0a e9 d3 ab 72 ec d2 20 0a e9 d3 ab 72 ee d2 e1 0a e9 d3 22 8b 14 d3 e4 0a e9 d3 22 8b ed d2 f3 0a e9 d3 22 8b ea d2 f8 0a e9 d3 22 8b ec d2 b6 0a e9 d3 ab 72 ed d2 f8 0a e9 d3 ab 72 ef d2 e1 0a e9 d3 ab 72 e8 d2 fb 0a e9 d3 e0 0a e8 d3 f9 0b e9 d3 13 88 e0 d2 fc 0a e9 d3 13 88 e9 d2 e1 0a e9 d3 13 88 16 d3 e1 0a e9 d3 e0 0a 7e d3 e1 0a e9 d3 13 88 eb d2 e1 0a e9 d3 52 69 63 68 e0 0a e9 d3 } //0a 00 
		$a_01_5 = {a4 6d 87 80 e0 0c e9 d3 e0 0c e9 d3 e0 0c e9 d3 ab 74 ea d2 eb 0c e9 d3 ab 74 ec d2 20 0c e9 d3 ab 74 ee d2 e1 0c e9 d3 22 8d 14 d3 e4 0c e9 d3 22 8d ed d2 f3 0c e9 d3 22 8d ea d2 f8 0c e9 d3 22 8d ec d2 b6 0c e9 d3 ab 74 ed d2 f8 0c e9 d3 ab 74 ef d2 e1 0c e9 d3 ab 74 e8 d2 fb 0c e9 d3 e0 0c e8 d3 fa 0d e9 d3 13 8e e0 d2 fc 0c e9 d3 13 8e e9 d2 e1 0c e9 d3 13 8e 16 d3 e1 0c e9 d3 e0 0c 7e d3 e1 0c e9 d3 13 8e eb d2 e1 0c e9 d3 52 69 63 68 e0 0c e9 d3 } //32 00 
		$a_01_6 = {53 74 65 61 6c 65 72 43 6c 69 65 6e 74 } //01 00  StealerClient
		$a_03_7 = {56 50 53 e8 01 00 00 00 00 58 89 c3 40 2d 00 90 01 02 00 2d 44 17 0c 10 05 3b 17 0c 10 80 3b cc 75 90 00 } //01 00 
		$a_01_8 = {4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  MSBuild.exe
		$a_01_9 = {52 00 41 00 49 00 44 00 58 00 70 00 65 00 72 00 74 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  RAIDXpert2.exe
		$a_01_10 = {4b 00 56 00 4d 00 20 00 56 00 69 00 73 00 69 00 6f 00 6e 00 20 00 56 00 69 00 65 00 77 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  KVM Vision Viewer.exe
		$a_01_11 = {66 00 69 00 6c 00 65 00 7a 00 69 00 6c 00 6c 00 61 00 2e 00 65 00 78 00 65 00 } //00 00  filezilla.exe
	condition:
		any of ($a_*)
 
}