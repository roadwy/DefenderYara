
rule HackTool_Win32_Keygen{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 61 69 64 65 6e 20 21 20 4c 7a 30 } //Raiden ! Lz0  01 00 
		$a_80_1 = {53 45 52 49 41 4c } //SERIAL  01 00 
		$a_80_2 = {47 65 6e 65 72 61 74 65 } //Generate  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_2{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {54 45 41 4d 20 5a 57 54 } //TEAM ZWT  01 00 
		$a_80_1 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 74 72 61 63 65 64 } //You have been traced  01 00 
		$a_80_2 = {4b 65 79 6d 61 6b 65 72 20 66 6f 72 } //Keymaker for  01 00 
		$a_80_3 = {26 47 65 6e 65 72 61 74 65 } //&Generate  01 00 
		$a_80_4 = {26 51 75 69 74 } //&Quit  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_3{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {63 6f 6d 2e 65 6d 62 61 72 63 61 64 65 72 6f 2e 45 61 73 65 55 53 5f 44 52 57 } //com.embarcadero.EaseUS_DRW  01 00 
		$a_80_1 = {54 44 43 50 5f 68 61 73 68 } //TDCP_hash  01 00 
		$a_80_2 = {44 43 50 63 72 79 70 74 32 } //DCPcrypt2  01 00 
		$a_80_3 = {4d 75 73 74 41 63 74 69 76 61 74 65 53 79 73 4d 65 6e 75 } //MustActivateSysMenu  01 00 
		$a_80_4 = {45 61 73 65 55 53 5f 44 52 57 2e 65 78 65 } //EaseUS_DRW.exe  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_4{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 6f 72 65 6c 20 50 72 6f 64 75 63 74 73 20 4b 65 79 67 65 6e } //Corel Products Keygen  01 00 
		$a_80_1 = {4b 65 79 67 65 6e } //Keygen  01 00 
		$a_80_2 = {41 63 74 69 76 61 74 69 6f 6e 20 43 6f 64 65 } //Activation Code  01 00 
		$a_80_3 = {5c 43 6f 72 65 6c 5c 53 74 75 62 46 72 61 6d 65 77 6f 72 6b 5c 56 53 50 } //\Corel\StubFramework\VSP  01 00 
		$a_80_4 = {46 43 6f 72 65 6c 44 72 61 77 58 38 41 63 74 69 76 61 74 69 6f 6e } //FCorelDrawX8Activation  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_5{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {4e 43 48 20 53 6f 66 74 77 61 72 65 20 4b 65 79 67 65 6e } //NCH Software Keygen  01 00 
		$a_80_1 = {4b 65 79 67 65 6e 2e 65 78 65 } //Keygen.exe  01 00 
		$a_80_2 = {73 65 63 75 72 65 2e 6e 63 68 2e 63 6f 6d 2e 61 75 } //secure.nch.com.au  01 00 
		$a_80_3 = {77 77 77 2e 6e 63 68 73 6f 66 74 77 61 72 65 2e 63 6f 6d } //www.nchsoftware.com  01 00 
		$a_80_4 = {52 61 64 69 58 58 31 31 } //RadiXX11  01 00 
		$a_80_5 = {50 61 74 63 68 20 48 6f 73 74 73 } //Patch Hosts  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_6{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 65 79 67 65 6e 6e 65 64 20 62 79 20 4b 61 69 5a 65 72 20 53 6f 5a 65 } //Keygenned by KaiZer SoZe  01 00 
		$a_80_1 = {47 66 58 20 64 6f 6e 65 20 42 79 20 66 53 74 44 2f 63 52 6f } //GfX done By fStD/cRo  01 00 
		$a_80_2 = {50 72 65 73 73 20 43 61 6c 63 75 6c 61 74 65 20 42 75 74 74 6f 6e } //Press Calculate Button  01 00 
		$a_80_3 = {45 6e 74 65 72 20 59 6f 75 72 20 4e 61 6d 65 } //Enter Your Name  01 00 
		$a_80_4 = {6b 65 79 67 65 6e } //keygen  01 00 
		$a_80_5 = {58 4d 4d 4f 44 } //XMMOD  01 00 
		$a_80_6 = {4d 55 53 49 43 } //MUSIC  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_7{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 72 69 74 65 5f 64 69 73 6b 5f 66 69 6c 65 } //write_disk_file  02 00 
		$a_80_1 = {6c 6f 61 64 5f 70 61 74 63 68 65 72 } //load_patcher  01 00 
		$a_80_2 = {53 65 61 72 63 68 41 6e 64 52 65 70 6c 61 63 65 } //SearchAndReplace  02 00 
		$a_80_3 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 50 61 74 63 68 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e } //<description>Patch</description>  01 00 
		$a_80_4 = {47 65 74 50 61 74 63 68 65 72 57 69 6e 64 6f 77 48 61 6e 64 6c 65 } //GetPatcherWindowHandle  02 00 
		$a_80_5 = {64 75 70 32 70 61 74 63 68 65 72 2e 64 6c 6c } //dup2patcher.dll  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_8{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 65 69 6c 20 47 65 6e 65 72 69 63 20 4b 65 79 67 65 6e 20 2d 20 45 44 47 45 } //Keil Generic Keygen - EDGE  01 00 
		$a_80_1 = {57 45 4c 43 4f 4d 45 20 54 4f 20 41 4e 4f 54 48 45 52 20 4e 49 43 45 20 4b 45 59 47 45 4e 20 46 52 4f 4d 20 59 4f 55 52 20 46 52 49 45 4e 44 53 20 41 54 20 45 44 47 45 } //WELCOME TO ANOTHER NICE KEYGEN FROM YOUR FRIENDS AT EDGE  01 00 
		$a_80_2 = {47 65 6e 2e 20 53 65 72 69 61 6c } //Gen. Serial  01 00 
		$a_80_3 = {4c 69 63 65 6e 73 65 20 44 65 74 61 69 6c 73 } //License Details  01 00 
		$a_80_4 = {4e 69 63 65 20 6d 75 73 69 63 20 63 6f 6d 70 6f 73 65 64 20 62 79 20 } //Nice music composed by   00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_9{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e 20 62 79 20 50 41 52 41 44 4f 58 } //01 00 
		$a_01_1 = {53 74 6f 70 2f 50 6c 61 79 20 4d 75 73 69 63 } //01 00 
		$a_01_2 = {47 65 6e 65 72 61 74 65 20 43 44 2d 4b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_10{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 64 61 79 61 6e 7a 61 69 2e 6d 65 } //04 00 
		$a_01_1 = {43 6f 72 65 6c 20 50 72 6f 64 75 63 74 73 20 4b 65 79 67 65 6e } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 53 50 72 6f 74 65 63 74 5c 4b 65 79 } //01 00 
		$a_01_3 = {61 73 70 72 5f 6b 65 79 73 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_11{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 75 00 74 00 6f 00 64 00 65 00 73 00 6b 00 20 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 } //01 00 
		$a_01_1 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 43 68 69 70 65 78 32 } //01 00 
		$a_01_2 = {46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30 20 } //01 00 
		$a_01_3 = {4d 69 63 72 6f 58 6d 20 42 79 20 4d 72 20 47 61 6d 65 72 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 64 20 42 79 20 4d 72 47 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_12{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 63 65 6e 73 65 20 66 69 6c 65 20 67 65 6e 65 72 61 74 65 64 21 } //01 00 
		$a_01_1 = {5b 20 53 46 58 20 62 79 20 67 68 69 64 6f 72 61 68 20 5d } //01 00 
		$a_01_2 = {46 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 21 } //01 00 
		$a_01_3 = {67 68 69 64 6f 72 61 68 40 6d 75 73 69 63 69 61 6e 2e 6f 72 67 } //01 00 
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 43 6f 6c 6c 61 6b 65 53 6f 66 74 77 61 72 65 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}