
rule Trojan_O97M_IcedID_SS_MTB{
	meta:
		description = "Trojan:O97M/IcedID.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 73 59 79 35 } //1 = "<div id='content'>fTtlc29sYy5
		$a_01_1 = {28 27 2f 2b 39 38 37 36 35 34 33 32 31 30 7a 79 78 77 76 75 74 73 72 71 70 6f 6e 6d 6c 6b 6a 69 68 67 66 65 64 63 62 61 5a 59 58 57 56 55 54 53 52 51 50 4f 4e 4d 4c 4b 4a 49 48 47 46 45 44 43 42 41 27 29 29 3b } //1 ('/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'));
		$a_01_2 = {74 69 76 65 58 4f 62 6a 65 63 74 28 } //1 tiveXObject(
		$a_01_3 = {3d 20 27 63 68 61 72 41 74 27 3b 66 6f 72 28 69 3d 30 3b 69 3c 36 34 3b 69 2b 2b 29 } //1 = 'charAt';for(i=0;i<64;i++)
		$a_01_4 = {66 6f 72 28 78 3d 30 3b 78 3c 4c 3b 78 2b 2b 29 } //1 for(x=0;x<L;x++)
		$a_01_5 = {2e 73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 } //1 .split('').reverse().join('')
		$a_01_6 = {2e 73 70 6c 69 74 28 27 7c 27 29 3b 76 61 72 } //1 .split('|');var
		$a_01_7 = {28 78 29 5d 3b 62 3d 28 62 3c 3c 36 29 2b 63 3b 6c 2b 3d 36 3b 77 68 69 6c 65 28 6c 3e 3d 38 29 7b 28 28 61 3d 28 62 3e 3e 3e 28 6c 2d 3d 38 29 29 26 30 78 66 66 29 7c 7c } //1 (x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_O97M_IcedID_SS_MTB_2{
	meta:
		description = "Trojan:O97M/IcedID.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 72 65 76 65 72 73 65 64 54 65 78 74 20 26 20 4d 69 64 28 [0-15] 2c 20 28 6c 65 6e 67 74 68 20 2d 20 69 29 2c 20 31 29 } //1
		$a_01_1 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //1 .Documents.Add.VBProject.VBComponents("ThisDocument").CodeModule
		$a_01_2 = {6d 65 6d 6f 72 79 4d 61 69 6e 42 75 74 74 6f 6e 20 3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d } //1 memoryMainButton = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & Application.Version & "\Word\Security\AccessVBOM
		$a_03_3 = {53 75 62 20 76 61 72 4d 61 69 6e 28 29 [0-03] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 6d 65 6d 6f 72 79 4d 61 69 6e 42 75 74 74 6f 6e 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_01_4 = {56 42 5f 4e 61 6d 65 20 3d 20 22 63 6f 75 6e 74 65 72 43 6f 70 79 50 61 73 74 65 } //1 VB_Name = "counterCopyPaste
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_O97M_IcedID_SS_MTB_3{
	meta:
		description = "Trojan:O97M/IcedID.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_03_0 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6d 33 33 78 61 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_1 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 31 62 77 73 6c 34 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_2 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 38 30 34 67 74 64 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_3 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 75 68 71 39 34 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_4 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6e 39 69 39 65 70 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_5 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6e 6d 35 6f 69 30 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //2
		$a_03_6 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f [0-0f] 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-02] 2e 63 61 62 22 2c 20 4f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*1) >=2
 
}
rule Trojan_O97M_IcedID_SS_MTB_4{
	meta:
		description = "Trojan:O97M/IcedID.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 69 7a 65 4e 61 6d 65 73 70 61 63 65 4d 65 6d 6f 72 79 20 3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 73 59 79 35 75 62 32 6c 30 63 47 46 44 65 57 46 79 63 6d 45 37 4b 54 49 67 4c 43 4a 6e 63 47 6f 75 5a 58 4e 68 59 6d 46 30 59 55 52 6c 62 47 4a 68 56 48 68 6c 5a 47 35 70 58 46 78 6a 61 57 78 69 64 58 42 63 58 48 4e 79 5a 58 4e 31 58 46 77 36 59 79 49 6f 5a 57 78 70 5a 6d 39 30 5a 58 5a 68 63 79 35 75 62 32 6c 30 63 47 46 44 65 57 46 79 } //2 sizeNamespaceMemory = "<div id='content'>fTtlc29sYy5ub2l0cGFDeWFycmE7KTIgLCJncGouZXNhYmF0YURlbGJhVHhlZG5pXFxjaWxidXBcXHNyZXN1XFw6YyIoZWxpZm90ZXZhcy5ub2l0cGFDeWFy
		$a_01_1 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 73 59 79 35 30 65 47 56 55 63 6e 52 77 4f 79 6b 79 49 43 77 69 5a 33 42 71 4c 6e 6c 79 62 32 31 6c 54 57 56 6e 59 58 4a 76 64 48 4e 63 58 47 4e 70 62 47 4a 31 63 46 78 63 63 33 4a 6c 63 33 56 63 58 44 70 6a 49 69 68 6c 62 47 6c 6d 62 33 52 6c 64 6d 46 7a 4c 6e 52 34 5a 56 52 79 64 48 41 37 4b 58 6c 6b 62 32 4a 6c 63 32 35 76 63 48 4e 6c 63 69 35 6c 62 48 52 70 56 48 4a 6c 5a 6d 5a 31 51 6d 35 6c 62 } //2 = "<div id='content'>fTtlc29sYy50eGVUcnRwOykyICwiZ3BqLnlyb21lTWVnYXJvdHNcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnR4ZVRydHA7KXlkb2Jlc25vcHNlci5lbHRpVHJlZmZ1Qm5lb
		$a_01_2 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 73 59 79 35 77 62 57 56 55 65 47 56 6b 62 6b 6c 7a 63 32 46 73 59 7a 73 70 4d 69 41 73 49 6d 64 77 61 69 35 75 61 57 46 4e 56 33 52 6d 5a 57 78 63 58 47 4e 70 62 47 4a 31 63 46 78 63 63 33 4a 6c 63 33 56 63 58 44 70 6a 49 69 68 6c 62 47 6c 6d 62 33 52 6c 64 6d 46 7a 4c 6e 42 74 5a 56 52 34 5a 57 52 75 53 58 4e 7a 59 57 78 6a 4f 79 6c 35 5a 47 39 69 5a 58 4e 75 62 33 } //2 = "<div id='content'>fTtlc29sYy5wbWVUeGVkbklzc2FsYzspMiAsImdwai5uaWFNV3RmZWxcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnBtZVR4ZWRuSXNzYWxjOyl5ZG9iZXNub3
		$a_01_3 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 73 59 79 35 6c 64 6d 39 74 5a 56 4a 34 62 32 4a 30 65 47 56 55 62 6d 39 70 64 48 42 6c 59 33 68 6c 4f 79 6b 79 49 43 77 69 5a 33 42 71 4c 6d 56 6a 59 58 42 7a 5a 57 31 68 54 6e 4a 68 64 6c 78 63 59 32 6c 73 59 6e 56 77 58 46 78 7a 63 6d 56 7a 64 56 78 63 4f 6d 4d 69 4b 47 56 73 61 57 5a 76 64 47 56 32 59 58 4d 75 5a 58 5a 76 62 57 56 53 65 47 39 69 64 48 68 6c 56 47 35 76 61 58 52 77 5a 57 4e 34 } //2 = "<div id='content'>fTtlc29sYy5ldm9tZVJ4b2J0eGVUbm9pdHBlY3hlOykyICwiZ3BqLmVjYXBzZW1hTnJhdlxcY2lsYnVwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMuZXZvbWVSeG9idHhlVG5vaXRwZWN4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}