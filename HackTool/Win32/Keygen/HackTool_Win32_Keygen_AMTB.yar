
rule HackTool_Win32_Keygen_AMTB{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e 6e 65 64 20 62 79 } //2 Keygenned by
		$a_01_1 = {46 46 46 4b 45 59 47 45 4e } //2 FFFKEYGEN
		$a_01_2 = {46 69 47 48 54 69 4e 47 20 46 4f 52 20 46 55 4e 20 50 52 45 53 45 4e 54 53 } //1 FiGHTiNG FOR FUN PRESENTS
		$a_01_3 = {53 65 56 65 4e 20 2f 20 46 46 46 } //1 SeVeN / FFF
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_AMTB_2{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 6f 64 65 64 20 62 79 20 4c 6f 72 64 20 42 6c 69 78 2f 54 53 5a } //Coded by Lord Blix/TSZ  2
		$a_80_1 = {52 65 67 69 73 74 72 61 74 69 6f 6e 20 43 6f 64 65 } //Registration Code  1
		$a_80_2 = {2d 4b 65 79 67 65 6e 2d } //-Keygen-  1
		$a_80_3 = {47 65 6e 65 72 61 74 65 } //Generate  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule HackTool_Win32_Keygen_AMTB_3{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_80_0 = {6c 64 72 5f 6b 65 79 67 65 6e } //ldr_keygen  3
		$a_80_1 = {57 68 79 20 73 6f 20 73 65 72 69 6f 75 73 3f 21 } //Why so serious?!  3
		$a_80_2 = {4c 69 6e 65 5a 65 72 30 } //LineZer0  3
		$a_80_3 = {4c 7a 30 20 32 6f 6f 39 } //Lz0 2oo9  3
		$a_80_4 = {41 20 50 72 6f 64 75 63 74 20 62 79 20 4c 7a 30 } //A Product by Lz0  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=15
 
}
rule HackTool_Win32_Keygen_AMTB_4{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {2a 4b 65 79 6d 61 6b 65 72 2a 20 62 79 20 54 65 61 6d 20 43 61 66 65 } //*Keymaker* by Team Cafe  2
		$a_80_1 = {4b 65 79 6d 61 6b 65 72 20 62 79 20 54 65 61 6d 20 43 61 66 65 } //Keymaker by Team Cafe  2
		$a_01_2 = {48 69 74 20 74 68 65 20 67 65 6e 65 72 61 74 65 20 62 75 74 74 6f 6e } //1 Hit the generate button
		$a_01_3 = {47 65 6e 65 72 61 74 65 } //1 Generate
		$a_80_4 = {53 65 72 69 61 6c 3a } //Serial:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_AMTB_5{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4b 65 79 67 65 6e 20 66 6f 72 20 49 6d 61 67 65 63 72 61 66 74 20 49 43 43 41 56 52 20 56 36 } //Keygen for Imagecraft ICCAVR V6  1
		$a_80_1 = {4b 65 79 67 65 6e 65 72 61 74 6f 72 20 6d 61 64 65 20 62 79 20 57 69 6e 42 69 6e 61 72 } //Keygenerator made by WinBinar  1
		$a_80_2 = {57 69 6e 42 69 6e 61 72 20 2f 20 44 65 6d 6f 6e } //WinBinar / Demon  1
		$a_80_3 = {59 6f 75 72 20 75 6e 6c 6f 63 6b 20 63 6f 64 65 20 68 65 72 65 3a } //Your unlock code here:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_AMTB_6{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {46 61 6b 65 20 4b 65 79 67 65 6e 2e 65 78 65 } //Fake Keygen.exe  1
		$a_80_1 = {6b 65 79 67 65 6e } //keygen  1
		$a_80_2 = {53 65 72 69 61 6c 20 4b 65 79 20 47 65 6e 65 72 61 74 6f 72 } //Serial Key Generator  1
		$a_80_3 = {4d 69 73 73 69 6e 67 20 64 34 64 78 2e 64 6c 6c 21 20 50 6c 65 61 73 65 20 72 75 6e 20 53 65 74 75 70 2e 65 78 65 20 74 6f 20 69 6e 73 74 61 6c 6c } //Missing d4dx.dll! Please run Setup.exe to install  1
		$a_80_4 = {70 69 72 61 74 65 5a } //pirateZ  1
		$a_80_5 = {54 45 41 4d 20 41 57 54 } //TEAM AWT  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Keygen_AMTB_7{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 49 5f 4b 65 79 67 65 6e 55 74 69 6c 73 } //DI_KeygenUtils  1
		$a_80_1 = {54 68 65 20 66 69 6c 65 28 73 29 20 68 61 73 20 62 65 65 6e 20 70 61 74 63 68 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //The file(s) has been patched successfully!  1
		$a_80_2 = {50 61 74 63 68 69 6e 67 20 69 6e 20 70 72 6f 67 72 65 73 73 2e 2e 2e } //Patching in progress...  1
		$a_80_3 = {44 49 5f 4b 65 79 67 65 6e 43 6f 72 65 } //DI_KeygenCore  1
		$a_80_4 = {44 49 5f 4b 65 79 67 65 6e 55 73 65 72 } //DI_KeygenUser  1
		$a_80_5 = {40 44 49 5f 4b 65 79 67 65 6e 50 61 74 63 68 65 72 } //@DI_KeygenPatcher  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Keygen_AMTB_8{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 6e 2d 67 65 6e 23 30 31 [0-0f] 46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30 } //1
		$a_03_1 = {43 72 61 63 6b 65 72 20 3a 20 4e 2d 47 65 6e [0-04] 50 72 6f 74 65 63 74 69 6f 6e 20 3a 20 43 72 61 70 70 79 20 56 42 20 21 21 21 [0-04] 54 68 6b 73 20 3a 20 4e 2d 47 65 6e 20 63 72 65 77 20 3b 29 [0-04] 4d 41 59 20 54 48 45 20 4c 55 4d 49 4e 4f 55 20 42 45 20 57 49 54 48 20 59 4f 55 20 21 21 [0-96] 45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a } //1
		$a_03_2 = {56 65 72 73 69 6f 6e 20 4d 6f 6e 6f 70 6f 73 74 65 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 } //1
		$a_01_3 = {2d 2d 2d 2d 2d 2d 2d 77 77 77 2e 63 65 72 72 6f 72 2e 74 6b 2d 2d } //1 -------www.cerror.tk--
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}