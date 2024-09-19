
rule Trojan_BAT_AsyncRAT_ARA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 b4 9c [0-02] 03 6f 2a 00 00 0a 17 da 33 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 d1 9d fe ?? ?? ?? 20 ?? ?? ?? ?? 66 20 ?? ?? ?? ?? 58 65 20 ?? ?? ?? ?? 61 66 65 66 20 ?? ?? ?? ?? 63 66 65 59 25 fe } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 1d 1a 5d 16 2d 02 1e 5a 1f 1f 5f 1c 2c fa 63 16 2d ed 61 1a 2c 01 } //2
		$a_80_1 = {53 65 6c 65 6e 61 47 6f 6d 65 7a 2e 50 72 6f 67 72 61 6d } //SelenaGomez.Program  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_4{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 07 91 8c ?? ?? ?? 01 03 07 8c ?? ?? ?? 01 03 8e b7 8c ?? ?? ?? 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 91 8c ?? ?? ?? 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 9c 07 17 d6 0b 07 08 31 c4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 20 ff 00 00 00 5f 2b 1d 03 6f ?? ?? ?? 0a 0c 2b 17 08 06 08 06 93 02 7b ?? ?? ?? 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8 } //2
		$a_01_1 = {57 69 6e 64 6f 2e 52 65 73 6f 75 72 63 65 73 } //2 Windo.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_6{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 08 9a 13 06 09 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 11 08 17 d6 13 08 11 08 11 09 8e b7 32 d8 } //2
		$a_01_1 = {66 75 6e 63 63 61 6c 6c 32 32 } //2 funccall22
		$a_01_2 = {52 65 44 5f 53 65 63 75 72 69 74 79 2e 72 65 73 6f 75 72 63 65 73 } //2 ReD_Security.resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_7{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 11 05 91 13 06 03 11 05 07 5d 91 13 07 11 07 08 20 00 01 00 00 5d 58 11 05 58 20 00 01 00 00 5d 13 08 11 06 11 08 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 09 06 11 05 11 09 9c 00 11 05 17 58 13 05 11 05 02 8e 69 fe 04 13 0a 11 0a 2d ac } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_8{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 74 2e 6d 65 2f 47 68 6f 73 74 48 61 63 6b 65 72 73 4e 65 74 77 6f 72 6b 3e } //2 <t.me/GhostHackersNetwork>
		$a_00_1 = {54 00 57 00 39 00 36 00 61 00 57 00 78 00 73 00 59 00 53 00 38 00 31 00 4c 00 6a 00 41 00 67 00 4b 00 } //2 TW96aWxsYS81LjAgK
		$a_00_2 = {55 00 32 00 39 00 6d 00 64 00 48 00 64 00 68 00 63 00 6d 00 56 00 63 00 } //2 U29mdHdhcmVc
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_9{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 37 32 2e 38 36 2e 39 36 2e 31 31 31 3a 38 30 38 30 2f 53 63 72 69 70 74 2e 70 73 31 } //3 ://172.86.96.111:8080/Script.ps1
		$a_01_1 = {55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 20 24 6c 6f 63 61 6c 50 61 74 68 } //2 Unblock-File $localPath
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 20 24 6c 6f 63 61 6c 50 61 74 68 } //2 powershell -ExecutionPolicy Bypass -File $localPath
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_10{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 8e 69 5d 1f 17 59 1f 17 58 02 08 02 8e 69 5d 1f 16 58 1f 16 59 91 07 08 07 8e 69 5d 1b 58 1a 58 1f 0b 58 1f 14 59 18 58 18 59 91 61 02 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 02 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3c 26 08 19 2c f8 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 3e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_11{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 00 2f 00 2f 00 78 00 73 00 70 00 79 00 6d 00 61 00 69 00 6e 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 69 00 6f 00 2f 00 74 00 65 00 65 00 74 00 2f 00 56 00 65 00 6e 00 6f 00 6d 00 44 00 65 00 6d 00 6f 00 2e 00 62 00 69 00 6e 00 } //2 ://xspymain.github.io/teet/VenomDemo.bin
		$a_00_1 = {43 00 6c 00 69 00 65 00 6e 00 74 00 5f 00 43 00 5f 00 2e 00 } //2 Client_C_.
		$a_00_2 = {73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 } //1 shellcode
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //2 DownloadData
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_12{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 02 11 06 91 13 07 02 11 06 02 11 06 17 58 91 9c 02 11 06 17 58 11 07 9c 00 11 06 18 58 13 06 11 06 11 04 17 59 fe 04 13 08 11 08 2d d2 } //2
		$a_03_1 = {00 11 09 09 59 7e ?? ?? ?? 04 8e 69 5d 13 0a 02 11 09 91 13 0b 08 18 5d 16 fe 01 13 0c 11 0c 39 17 00 00 00 00 06 11 09 11 0b 7e ?? ?? ?? 04 11 0a 91 59 d2 9c 00 38 ?? ?? ?? ?? 00 06 11 09 11 0b 7e ?? ?? ?? 04 11 0a 91 58 d2 9c 00 00 11 09 17 58 13 09 11 09 11 04 fe 04 13 0d 11 0d 2d a0 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_13{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  1
		$a_80_1 = {56 65 6e 6f 6d 42 79 56 65 6e 6f 6d } //VenomByVenom  2
		$a_80_2 = {50 61 73 74 65 5f 62 69 6e } //Paste_bin  2
		$a_80_3 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } ///c schtasks /create /f /sc onlogon /rl highest /tn  2
		$a_80_4 = {6d 61 73 74 65 72 4b 65 79 20 63 61 6e 20 6e 6f 74 20 62 65 20 6e 75 6c 6c 20 6f 72 20 65 6d 70 74 79 2e } //masterKey can not be null or empty.  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=9
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_14{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 61 76 61 55 70 64 61 74 65 } //2 JavaUpdate
		$a_01_1 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //2 capCreateCaptureWindowA
		$a_00_2 = {69 00 73 00 20 00 74 00 61 00 6d 00 70 00 65 00 72 00 65 00 64 00 2e 00 } //2 is tampered.
		$a_00_3 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //2 {11111-22222-40001-00001}
		$a_00_4 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //2 {11111-22222-40001-00002}
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}
rule Trojan_BAT_AsyncRAT_ARA_MTB_15{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 66 65 65 34 65 64 34 38 2d 35 37 33 32 2d 34 35 61 61 2d 39 62 34 30 2d 38 38 32 31 63 66 66 35 31 65 32 32 } //2 $fee4ed48-5732-45aa-9b40-8821cff51e22
		$a_00_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 } //1 SELECT * FROM Win32_VideoController
		$a_00_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 2f 00 74 00 20 00 31 00 20 00 26 00 26 00 20 00 44 00 45 00 4c 00 20 00 2f 00 66 00 } //1 /c timeout /t 1 && DEL /f
		$a_00_3 = {2f 00 63 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 68 00 } //1 /c attrib +h
		$a_01_4 = {41 6e 74 69 56 4d 5f 47 50 55 } //1 AntiVM_GPU
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}