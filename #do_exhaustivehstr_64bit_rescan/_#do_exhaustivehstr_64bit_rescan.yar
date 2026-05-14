
rule _#do_exhaustivehstr_64bit_rescan{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 73 68 65 6c 6c } //1 .shell
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_2{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 6f 6c 64 69 65 72 2e 64 6c 6c } //1 Soldier.dll
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_3{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_40_0 = {8b 49 18 48 3b 0d 40 fa 00 00 00 } //1
	condition:
		((#a_40_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_4{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 49 4e 4a 45 43 54 44 41 54 41 7d } //1 {INJECTDATA}
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_5{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 69 64 65 6c 6f 61 64 2e 70 64 62 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_6{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 48 41 43 4b 45 44 20 42 59 20 48 41 4e 44 41 4c 41 0d 0a 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_7{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 55 49 54 4b 41 5f 4f 4e 45 46 49 4c 45 5f 50 41 52 45 4e 54 } //1 NUITKA_ONEFILE_PARENT
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_8{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 68 61 74 67 70 74 2e 70 64 62 00 09 00 00 00 28 00 00 00 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_9{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 } //1 AntiVir
		$a_01_1 = {43 00 44 00 61 00 74 00 61 00 } //1 CData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_10{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 61 69 6c 65 64 20 74 6f 20 72 75 6e 20 74 61 73 6b 6b 69 6c 6c 20 66 6f 72 20 50 49 44 20 21 } //1 failed to run taskkill for PID !
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_11{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //2 DeviceIoControl
		$a_80_1 = {2e 62 6c 66 } //.blf  1
		$a_80_2 = {4c 4f 47 3a } //LOG:  1
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_12{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 75 00 70 00 6f 00 6f 00 6e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 36 00 34 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_13{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 6b 65 79 6c 6f 67 67 65 72 2e 72 73 } //1 src\keylogger.rs
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 5f 66 69 6c 65 } //1 keylogger_file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_14{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 63 6c 6f 73 65 64 20 6f 72 20 65 72 72 6f 72 20 6f 63 63 75 72 72 65 64 2e } //1 Connection closed or error occurred.
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_15{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 61 6d 65 47 61 6d 65 2e 65 78 65 00 48 65 6c 6c 6f 57 6f 72 6c 64 } //1
		$a_01_1 = {6a 65 6c 75 73 20 52 41 54 } //1 jelus RAT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_16{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 6c 75 74 74 65 72 57 69 6e 64 6f 77 73 5f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 5f 49 6e 69 74 69 61 6c 69 7a 65 } //1 FlutterWindows_WindowManager_Initialize
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_17{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 74 6f 73 6b 72 6e 6c } //1 Ntoskrnl
		$a_01_1 = {46 6c 74 4d 67 72 } //1 FltMgr
		$a_01_2 = {4e 65 74 69 6f } //1 Netio
		$a_01_3 = {43 72 61 73 68 44 6d 70 } //1 CrashDmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_18{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 } //1 Go buildinf
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 68 61 63 6b 69 72 62 79 2f 73 6b 75 6c 64 } //1 github.com/hackirby/skuld
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_19{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 69 02 00 00 01 01 00 00 66 0f ef c0 48 8d b4 24 b0 05 00 00 66 0f 7f 46 20 66 0f 7f 46 10 66 0f 7f 06 48 89 f1 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_20{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 63 68 61 6e 6e 65 6c } //1 Schannel
		$a_01_1 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 DecryptMessage
		$a_01_2 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_21{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 57 69 6e 69 6e 65 74 5f 50 72 6f 74 6f 63 6f 6c 40 40 } //1 .?AVCWininet_Protocol@@
		$a_01_1 = {43 4d 53 5f 43 6f 6e 74 65 6e 74 49 6e 66 6f } //1 CMS_ContentInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_22{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b c3 39 9d 40 02 00 00 76 ?? 4c 8b cb 4c 8d 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 f7 e8 c1 fa ?? 8b c2 c1 e8 1f 03 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_23{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {65 6e 64 00 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 75 4e 74 41 64 64 41 74 6f 6d 2e 62 61 73 69 63 5f 73 74 72 69 6e 67 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_24{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 65 78 70 6f 72 74 65 72 } //1 downloadexporter
		$a_01_1 = {73 68 65 6c 6c 73 6c 65 65 70 73 6c 69 63 65 } //1 shellsleepslice
		$a_01_2 = {75 70 6c 6f 61 64 20 25 76 3d 25 76 2c } //1 upload %v=%v,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_25{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c 20 4f 75 74 2d 46 69 6c 65 20 2d 45 6e 63 6f 64 69 6e 67 20 75 6e 69 63 6f 64 65 } //1 | Out-File -Encoding unicode
		$a_01_1 = {63 6d 64 5f 74 79 70 65 } //1 cmd_type
		$a_01_2 = {63 6d 64 5f 62 6f 64 79 } //1 cmd_body
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_26{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
		$a_01_1 = {79 67 67 64 72 61 73 69 6c 2d 6e 65 74 77 6f 72 6b } //1 yggdrasil-network
		$a_01_2 = {6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 } //1 kbinani/screenshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_27{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 31 39 37 35 5c 44 6f 77 6e 6c 6f 61 64 73 5c 54 65 63 68 6e 69 63 61 6c 44 69 72 65 63 74 6f 72 5c 53 75 6d 61 74 72 61 50 44 46 2e 65 78 65 } //1 C:\Users\1975\Downloads\TechnicalDirector\SumatraPDF.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_28{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 74 68 65 6e 74 2d 74 65 61 6d 5c 69 65 5c 42 69 6e 61 72 69 65 73 5c 43 6f 6e 74 65 6e 74 } //1 \thent-team\ie\Binaries\Content
		$a_01_1 = {67 00 65 00 74 00 6d 00 70 00 6f 00 66 00 66 00 65 00 72 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_29{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 74 43 6c 6f 73 65 00 4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 00 4e 74 52 65 61 64 46 69 6c 65 } //1
		$a_01_1 = {50 00 4e 00 47 00 61 00 00 00 50 00 4e 00 47 00 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_30{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 65 73 68 41 67 65 6e 74 5c 4d 65 73 68 41 67 65 6e 74 5c 52 65 6c 65 61 73 65 5c 4d 65 73 68 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //1 \MeshAgent\MeshAgent\Release\MeshService64.pdb
		$a_01_1 = {4d 65 73 68 43 65 6e 74 72 61 6c 52 6f 6f 74 } //1 MeshCentralRoot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_31{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 6c 74 72 61 56 4e 43 } //1 UltraVNC
		$a_01_1 = {56 4e 43 20 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e } //1 VNC authentication
		$a_01_2 = {76 6e 63 76 69 65 77 65 72 2e 65 78 65 } //1 vncviewer.exe
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 75 76 6e 63 2e 63 6f 6d } //1 https://www.uvnc.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_32{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 } //1 Go buildinf
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 6f 6f 6e 64 34 72 6b 2f 68 61 63 6b 62 72 6f 77 73 65 72 64 61 74 61 2f 63 6d 64 2f 68 61 63 6b 2d 62 72 6f 77 73 65 72 2d 64 61 74 61 } //1 github.com/moond4rk/hackbrowserdata/cmd/hack-browser-data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_33{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 72 64 6c 6c 66 69 6e 61 6c 2e 64 6c 6c } //3 yourdllfinal.dll
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 } //1 Go build ID: "
		$a_01_2 = {47 4f 44 45 42 55 47 3a 20 75 6e 6b 6e 6f 77 6e 20 63 70 75 20 66 65 61 74 75 72 65 } //1 GODEBUG: unknown cpu feature
		$a_01_3 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_64bit_rescan_34{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 00 43 00 68 00 72 00 6f 00 6d 00 65 00 3a 00 3a 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 3a 00 3a 00 49 00 73 00 56 00 61 00 6c 00 69 00 64 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 54 00 6f 00 4c 00 6f 00 61 00 64 00 41 00 5d 00 } //1 [Chrome::Protector::IsValidLibraryToLoadA]
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_35{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
		$a_01_1 = {50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 } //1 PRI * HTTP/2.0
		$a_01_2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 62 69 6e 61 72 79 } //1 application/binary
		$a_01_3 = {52 65 71 75 65 73 74 2d 53 74 72 65 61 6d 20 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64 2e } //1 Request-Stream not implemented.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_64bit_rescan_36{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 6c 00 65 00 61 00 73 00 65 00 20 00 30 00 2e 00 37 00 36 00 20 00 28 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 65 00 6d 00 62 00 65 00 64 00 64 00 65 00 64 00 20 00 68 00 65 00 6c 00 70 00 29 00 } //100 Release 0.76 (without embedded help)
		$a_01_1 = {6e 61 6d 65 3d 22 50 75 54 54 59 22 } //100 name="PuTTY"
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100) >=200
 
}
rule _#do_exhaustivehstr_64bit_rescan_37{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 00 30 00 32 00 33 00 20 00 55 00 6c 00 74 00 72 00 61 00 56 00 4e 00 43 00 20 00 74 00 65 00 61 00 6d 00 20 00 6d 00 65 00 6d 00 62 00 65 00 72 00 73 00 } //1 2023 UltraVNC team members
		$a_01_1 = {55 00 6c 00 74 00 72 00 61 00 56 00 4e 00 43 00 } //1 UltraVNC
		$a_01_2 = {76 6e 63 76 69 65 77 65 72 2e 65 78 65 } //1 vncviewer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_38{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 79 74 65 73 01 05 43 61 75 73 65 01 05 43 68 64 69 72 01 05 43 68 6d 6f 64 01 05 43 68 6f 77 6e 01 05 43 6c 61 73 73 01 05 43 6c 6f 63 6b 01 05 43 6c 6f 6e 65 01 05 43 6c 6f 73 65 01 05 43 6f 65 66 66 01 05 43 75 72 76 65 09 05 43 75 72 76 65 01 05 45 6d 70 74 79 01 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_39{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 66 6d 70 65 67 2e 64 6c 6c } //1 ffmpeg.dll
		$a_01_1 = {61 76 63 6f 64 65 63 5f 70 61 72 61 6d 65 74 65 72 73 5f 74 6f 5f 63 6f 6e 74 65 78 74 } //1 avcodec_parameters_to_context
		$a_01_2 = {61 76 63 6f 64 65 63 5f 72 65 63 65 69 76 65 5f 66 72 61 6d 65 } //1 avcodec_receive_frame
		$a_01_3 = {61 76 63 6f 64 65 63 5f 73 65 6e 64 5f 70 61 63 6b 65 74 } //1 avcodec_send_packet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_64bit_rescan_40{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 64 72 44 6c 6c 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 [41-5a] 90 05 0c 03 61 2d 7a 00 } //1
		$a_03_1 = {4c 64 72 44 6c 6c 2e 64 6c 6c 00 [41-5a] 90 05 0c 03 61 2d 7a 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_41{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {6d 69 6e 6b 65 72 6e 65 6c 5c 63 72 74 73 5c 75 63 72 74 5c 73 72 63 5c 61 70 70 63 72 74 5c 6d 69 73 63 5c 73 69 67 6e 61 6c 2e 63 70 70 } //minkernel\crts\ucrt\src\appcrt\misc\signal.cpp  1
		$a_80_1 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //SizeofResource  1
		$a_80_2 = {46 69 6e 64 52 65 73 6f 75 72 63 65 57 } //FindResourceW  1
		$a_80_3 = {69 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //installer.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_42{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 53 00 75 00 6d 00 61 00 74 00 72 00 61 00 50 00 44 00 46 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //100 \\.\pipe\SumatraPDFLogger
		$a_01_1 = {53 00 75 00 6d 00 61 00 74 00 72 00 61 00 57 00 67 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 57 00 69 00 6e 00 43 00 6c 00 61 00 73 00 73 00 } //100 SumatraWgDefaultWinClass
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100) >=200
 
}
rule _#do_exhaustivehstr_64bit_rescan_43{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 69 62 72 61 72 79 5c 73 74 64 5c 73 72 63 5c 73 79 73 5c 77 69 6e 64 6f 77 73 5c 6e 65 74 2e 72 73 } //1 library\std\src\sys\windows\net.rs
		$a_01_1 = {6c 69 62 72 61 72 79 5c 73 74 64 5c 73 72 63 5c 73 79 73 5f 63 6f 6d 6d 6f 6e 5c 6e 65 74 2e 72 73 } //1 library\std\src\sys_common\net.rs
		$a_01_2 = {6c 69 62 72 61 72 79 5c 73 74 64 5c 73 72 63 5c 69 6f 5c 72 65 61 64 62 75 66 2e 72 73 } //1 library\std\src\io\readbuf.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_44{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6f 6c 69 63 69 65 73 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 45 78 74 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 43 4c 53 49 44 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 09 09 76 61 6c 20 27 25 50 4c 55 47 49 4e 5f 43 4c 53 49 44 25 27 20 3d 20 73 20 27 31 27 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_45{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 67 77 2d 77 36 34 20 72 75 6e 74 69 6d 65 20 66 61 69 6c 75 72 65 3a } //1 Mingw-w64 runtime failure:
		$a_01_1 = {47 4e 55 20 41 53 20 32 2e 34 34 } //1 GNU AS 2.44
		$a_01_2 = {47 43 43 3a 20 28 4d 69 6e 47 57 2d 57 36 34 20 78 38 36 5f 36 34 2d 75 63 72 74 2d 70 6f 73 69 78 2d 73 65 68 2c 20 62 75 69 6c 74 20 62 79 20 42 72 65 63 68 74 20 53 61 6e 64 65 72 73 2c 20 72 32 29 20 31 34 2e 32 2e 30 } //1 GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r2) 14.2.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_46{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 63 72 79 70 74 2e 64 6c 6c } //1 bcrypt.dll
		$a_01_1 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 } //1 FindFirstFile
		$a_01_2 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 } //1 FindNextFile
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f } //1 GetLocaleInfo
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 50 72 65 63 69 73 65 41 73 46 69 6c 65 54 69 6d 65 } //1 GetSystemTimePreciseAsFileTime
		$a_01_6 = {47 65 74 54 65 6d 70 50 61 74 68 32 } //1 GetTempPath2
		$a_01_7 = {4d 47 46 31 } //1 MGF1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#do_exhaustivehstr_64bit_rescan_47{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 3a 00 3a 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 45 00 76 00 65 00 6e 00 74 00 73 00 5d 00 } //1 [Monitor::InjectorMonitor::CreateMonitoringEvents]
		$a_01_1 = {2e 3f 41 56 45 78 74 65 6e 73 69 6f 6e 40 50 72 65 66 65 72 65 6e 63 65 73 40 4a 73 6f 6e 40 53 70 65 65 64 42 69 74 40 40 } //1 .?AVExtension@Preferences@Json@SpeedBit@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_48{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 51 75 65 72 79 20 66 61 69 6c 65 64 20 66 6f 72 20 25 64 20 62 79 74 65 73 20 61 74 20 61 64 64 72 65 73 73 20 25 70 } //1 VirtualQuery failed for %d bytes at address %p
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 30 78 25 78 } //1 VirtualProtect failed with code 0x%x
		$a_01_2 = {55 6e 6b 6e 6f 77 6e 20 70 73 65 75 64 6f 20 72 65 6c 6f 63 61 74 69 6f 6e 20 70 72 6f 74 6f 63 6f 6c 20 76 65 72 73 69 6f 6e 20 25 64 } //1 Unknown pseudo relocation protocol version %d
		$a_01_3 = {25 64 20 62 69 74 20 70 73 65 75 64 6f 20 72 65 6c 6f 63 61 74 69 6f 6e 20 61 74 20 25 70 20 6f 75 74 20 6f 66 20 72 61 6e 67 65 2c 20 74 61 72 67 65 74 69 6e 67 20 25 70 2c 20 79 69 65 6c 64 69 6e 67 20 74 68 65 20 76 61 6c 75 65 20 25 70 2e } //1 %d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_49{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 58 50 20 36 34 2d 62 69 74 20 45 64 69 74 69 6f 6e 20 56 65 72 73 69 6f 6e 20 32 30 30 33 20 6f 72 20 6e 65 77 65 72 20 73 68 6f 75 6c 64 20 62 65 20 75 73 65 64 2e } //1 Windows XP 64-bit Edition Version 2003 or newer should be used.
		$a_01_1 = {50 6c 65 61 73 65 20 76 65 72 69 66 79 20 74 68 61 74 20 62 6f 74 68 20 74 68 65 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 20 61 6e 64 20 74 68 65 20 70 72 6f 63 65 73 73 6f 72 20 73 75 70 70 6f 72 74 20 49 6e 74 65 6c 28 52 29 20 41 56 58 32 2c 20 42 4d 49 2c 20 4c 5a 43 4e 54 2c 20 48 4c 45 2c 20 52 54 4d 20 61 6e 64 20 46 4d 41 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e } //1 Please verify that both the operating system and the processor support Intel(R) AVX2, BMI, LZCNT, HLE, RTM and FMA instructions.
		$a_40_2 = {90 fa 00 00 41 b8 01 00 00 00 ff d0 48 85 c0 01 } //1
		$a_44_3 = {c8 45 89 c1 41 29 c1 41 83 f9 01 74 00 00 78 f9 00 00 01 00 01 00 01 00 00 01 00 ec 03 07 2a 73 74 72 69 6e 67 00 07 72 75 6e 74 69 6d 65 00 07 2a 75 69 6e 74 31 36 00 07 2a 75 69 6e 74 33 32 } //3584
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_40_2  & 1)*1+(#a_44_3  & 1)*3584) >=4
 
}
rule _#do_exhaustivehstr_64bit_rescan_50{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 2a 73 74 72 69 6e 67 00 07 72 75 6e 74 69 6d 65 00 07 2a 75 69 6e 74 31 36 00 07 2a 75 69 6e 74 33 32 00 07 2a 75 69 6e 74 36 34 00 07 2a 5b 5d 75 69 6e 74 00 07 70 74 72 53 69 7a 65 ?? 07 66 75 6e 63 6f 66 66 00 07 66 69 6c 65 74 61 62 00 07 63 6f 76 63 74 72 73 00 07 68 61 73 6d 61 69 6e 00 07 74 79 70 65 6d 61 70 00 07 74 65 78 74 4f 66 66 00 07 6e 61 6d 65 4f 66 66 00 07 73 72 63 46 75 6e 63 00 07 6e 70 63 64 61 74 61 00 07 73 74 61 72 74 50 43 00 07 73 74 61 72 74 53 50 00 07 69 73 45 6d 70 74 79 00 07 74 61 6b 65 41 6c 6c 00 07 6f 62 6a 42 61 73 65 00 07 70 75 73 68 41 6c 6c 04 03 70 6f 70 30 14 00 00 00 07 77 61 69 74 69 6e 67 00 07 72 75 6e 6e 69 6e 67 00 07 7a 6f 6d 62 69 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_51{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 25 00 70 00 3a 00 25 00 70 00 5d 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 20 00 25 00 64 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 20 00 55 00 52 00 4c 00 20 00 74 00 6f 00 20 00 27 00 25 00 2e 00 31 00 30 00 32 00 34 00 73 00 7e 00 27 00 } //1 [%p:%p] inject %d change URL to '%.1024s~'
		$a_01_1 = {52 00 20 00 49 00 4e 00 49 00 2d 00 66 00 69 00 6c 00 65 00 3a 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 49 00 4e 00 49 00 2d 00 65 00 6e 00 63 00 3a 00 6e 00 65 00 77 00 28 00 42 00 41 00 53 00 45 00 36 00 34 00 58 00 7c 00 4d 00 45 00 54 00 41 00 29 00 78 00 36 00 34 00 } //1 R INI-file:encrypted INI-enc:new(BASE64X|META)x64
		$a_01_2 = {5b 00 25 00 70 00 3a 00 25 00 70 00 5d 00 20 00 45 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 [%p:%p] E timeout injecting content
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_52{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 2e 49 64 65 6e 74 69 74 79 2e 64 6c 6c } //1 Microsoft.Identity.dll
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 70 6d 70 72 6f 78 79 2e 64 6c 6c 2e 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 C:\Windows\System32\npmproxy.dll.DllCanUnloadNow
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 70 6d 70 72 6f 78 79 2e 64 6c 6c 2e 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 C:\Windows\System32\npmproxy.dll.DllGetClassObject
		$a_01_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 70 6d 70 72 6f 78 79 2e 64 6c 6c 2e 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 C:\Windows\System32\npmproxy.dll.DllRegisterServer
		$a_01_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 70 6d 70 72 6f 78 79 2e 64 6c 6c 2e 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 C:\Windows\System32\npmproxy.dll.DllUnregisterServer
		$a_01_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 70 6d 70 72 6f 78 79 2e 64 6c 6c 2e 47 65 74 50 72 6f 78 79 44 6c 6c 49 6e 66 6f } //1 C:\Windows\System32\npmproxy.dll.GetProxyDllInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_64bit_rescan_53{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 8a 44 0b 0c 49 8b ca 49 ff c2 83 e1 03 42 32 44 01 04 42 32 04 01 41 88 01 49 ff c1 48 ff ca 75 de } //1
		$a_03_1 = {02 14 08 48 ff c1 49 3b ca 72 ?? 49 8b cc 48 39 4d ?? 76 ?? 48 8d 45 ?? 48 83 7d ?? 10 48 0f 43 45 ?? 30 14 08 48 ff c1 } //1
		$a_01_2 = {8b c2 25 03 00 00 80 7d 07 ff c8 83 c8 fc ff c0 48 63 c8 43 0f b6 44 01 0c 49 ff c0 32 44 31 04 ff c2 32 04 31 41 88 40 ff 48 ff cb 75 d2 } //1
		$a_03_3 = {41 b8 0b 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 4d ?? e8 ?? ?? ?? ?? 48 c7 45 ?? 07 00 00 00 48 89 7d ?? 66 89 7c 24 ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 83 38 00 75 05 } //1
		$a_01_4 = {48 8d 83 fa fe ff 7f 48 85 c0 74 12 0f b6 04 0a 84 c0 74 0a 88 01 48 ff c1 48 ff cb 75 e2 48 85 db 75 03 48 ff c9 } //1
		$a_01_5 = {2f 00 6a 00 73 00 61 00 64 00 6b 00 62 00 77 00 64 00 66 00 67 00 3f 00 75 00 3d 00 25 00 73 00 26 00 61 00 3d 00 25 00 73 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_54{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,6d 00 6d 00 13 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 4d 61 69 6e } //100 ServiceMain
		$a_01_1 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 41 64 64 50 61 74 63 68 54 6f 41 72 72 61 79 } //1 cJSONUtils_AddPatchToArray
		$a_01_2 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 41 70 70 6c 79 50 61 74 63 68 65 73 } //1 cJSONUtils_ApplyPatches
		$a_01_3 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 41 70 70 6c 79 50 61 74 63 68 65 73 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_ApplyPatchesCaseSensitive
		$a_01_4 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 46 69 6e 64 50 6f 69 6e 74 65 72 46 72 6f 6d 4f 62 6a 65 63 74 54 6f } //1 cJSONUtils_FindPointerFromObjectTo
		$a_01_5 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 6e 65 72 61 74 65 4d 65 72 67 65 50 61 74 63 68 } //1 cJSONUtils_GenerateMergePatch
		$a_01_6 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 6e 65 72 61 74 65 4d 65 72 67 65 50 61 74 63 68 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_GenerateMergePatchCaseSensitive
		$a_01_7 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 6e 65 72 61 74 65 50 61 74 63 68 65 73 } //1 cJSONUtils_GeneratePatches
		$a_01_8 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 6e 65 72 61 74 65 50 61 74 63 68 65 73 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_GeneratePatchesCaseSensitive
		$a_01_9 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 74 50 6f 69 6e 74 65 72 } //1 cJSONUtils_GetPointer
		$a_01_10 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 47 65 74 50 6f 69 6e 74 65 72 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_GetPointerCaseSensitive
		$a_01_11 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 4d 65 72 67 65 50 61 74 63 68 } //1 cJSONUtils_MergePatch
		$a_01_12 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 4d 65 72 67 65 50 61 74 63 68 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_MergePatchCaseSensitive
		$a_01_13 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 53 6f 72 74 4f 62 6a 65 63 74 } //1 cJSONUtils_SortObject
		$a_01_14 = {63 4a 53 4f 4e 55 74 69 6c 73 5f 53 6f 72 74 4f 62 6a 65 63 74 43 61 73 65 53 65 6e 73 69 74 69 76 65 } //1 cJSONUtils_SortObjectCaseSensitive
		$a_01_15 = {63 4a 53 4f 4e 5f 41 64 64 41 72 72 61 79 54 6f 4f 62 6a 65 63 74 } //1 cJSON_AddArrayToObject
		$a_01_16 = {63 4a 53 4f 4e 5f 41 64 64 42 6f 6f 6c 54 6f 4f 62 6a 65 63 74 } //1 cJSON_AddBoolToObject
		$a_01_17 = {63 4a 53 4f 4e 5f 41 64 64 46 61 6c 73 65 54 6f 4f 62 6a 65 63 74 } //1 cJSON_AddFalseToObject
		$a_01_18 = {63 4a 53 4f 4e 5f 41 64 64 49 74 65 6d 52 65 66 65 72 65 6e 63 65 54 6f 41 72 72 61 79 } //1 cJSON_AddItemReferenceToArray
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=109
 
}
rule _#do_exhaustivehstr_64bit_rescan_55{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 49 00 00 "
		
	strings :
		$a_01_0 = {43 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 69 6d 70 6c 69 63 69 74 20 63 6c 6f 73 75 72 65 20 69 6e 20 41 4f 54 21 } //1 Cannot create implicit closure in AOT!
		$a_01_1 = {43 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 73 6e 61 70 73 68 6f 74 73 20 6f 6e 20 61 6e 20 41 4f 54 20 72 75 6e 74 69 6d 65 2e } //1 Cannot create snapshots on an AOT runtime.
		$a_01_2 = {25 73 3a 20 43 61 6e 6e 6f 74 20 63 6f 6d 70 69 6c 65 20 6f 6e 20 61 6e 20 41 4f 54 20 72 75 6e 74 69 6d 65 2e } //1 %s: Cannot compile on an AOT runtime.
		$a_01_3 = {54 68 69 73 20 56 4d 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 6f 75 74 20 73 75 70 70 6f 72 74 20 66 6f 72 20 41 4f 54 20 63 6f 6d 70 69 6c 61 74 69 6f 6e 2e } //1 This VM was built without support for AOT compilation.
		$a_01_4 = {4a 49 54 20 61 70 70 20 73 6e 61 70 73 68 6f 74 73 20 63 61 6e 6e 6f 74 20 62 65 20 74 61 6b 65 6e 20 66 72 6f 6d 20 61 6e 20 41 4f 54 20 72 75 6e 74 69 6d 65 } //1 JIT app snapshots cannot be taken from an AOT runtime
		$a_01_5 = {4e 6f 20 6f 62 66 75 73 63 61 74 69 6f 6e 20 6d 61 70 20 74 6f 20 73 61 76 65 20 6f 6e 20 61 6e 20 41 4f 54 20 72 75 6e 74 69 6d 65 2e } //1 No obfuscation map to save on an AOT runtime.
		$a_01_6 = {25 73 3a 20 41 6c 6c 20 63 6c 61 73 73 65 73 20 61 72 65 20 61 6c 72 65 61 64 79 20 66 69 6e 61 6c 69 7a 65 64 20 69 6e 20 41 4f 54 20 72 75 6e 74 69 6d 65 2e } //1 %s: All classes are already finalized in AOT runtime.
		$a_01_7 = {44 61 72 74 5f 50 72 65 63 6f 6d 70 69 6c 65 } //1 Dart_Precompile
		$a_01_8 = {44 61 72 74 5f 50 72 65 70 61 72 65 54 6f 41 62 6f 72 74 } //1 Dart_PrepareToAbort
		$a_01_9 = {44 61 72 74 5f 50 72 6f 70 61 67 61 74 65 45 72 72 6f 72 } //1 Dart_PropagateError
		$a_01_10 = {44 61 72 74 5f 52 65 54 68 72 6f 77 45 78 63 65 70 74 69 6f 6e } //1 Dart_ReThrowException
		$a_01_11 = {44 61 72 74 5f 52 65 63 6f 72 64 54 69 6d 65 6c 69 6e 65 45 76 65 6e 74 } //1 Dart_RecordTimelineEvent
		$a_01_12 = {44 61 72 74 5f 52 65 67 69 73 74 65 72 48 65 61 70 53 61 6d 70 6c 69 6e 67 43 61 6c 6c 62 61 63 6b } //1 Dart_RegisterHeapSamplingCallback
		$a_01_13 = {44 61 72 74 5f 52 65 67 69 73 74 65 72 49 73 6f 6c 61 74 65 53 65 72 76 69 63 65 52 65 71 75 65 73 74 43 61 6c 6c 62 61 63 6b } //1 Dart_RegisterIsolateServiceRequestCallback
		$a_01_14 = {44 61 72 74 5f 52 65 67 69 73 74 65 72 52 6f 6f 74 53 65 72 76 69 63 65 52 65 71 75 65 73 74 43 61 6c 6c 62 61 63 6b } //1 Dart_RegisterRootServiceRequestCallback
		$a_01_15 = {44 61 72 74 5f 52 65 70 6f 72 74 53 75 72 76 69 76 69 6e 67 41 6c 6c 6f 63 61 74 69 6f 6e 73 } //1 Dart_ReportSurvivingAllocations
		$a_01_16 = {44 61 72 74 5f 53 63 6f 70 65 41 6c 6c 6f 63 61 74 65 } //1 Dart_ScopeAllocate
		$a_01_17 = {44 61 72 74 5f 53 65 6e 64 50 6f 72 74 47 65 74 49 64 } //1 Dart_SendPortGetId
		$a_01_18 = {44 61 72 74 5f 53 65 72 76 69 63 65 53 65 6e 64 44 61 74 61 45 76 65 6e 74 } //1 Dart_ServiceSendDataEvent
		$a_01_19 = {44 61 72 74 5f 53 65 74 42 6f 6f 6c 65 61 6e 52 65 74 75 72 6e 56 61 6c 75 65 } //1 Dart_SetBooleanReturnValue
		$a_01_20 = {44 61 72 74 5f 53 65 74 43 75 72 72 65 6e 74 55 73 65 72 54 61 67 } //1 Dart_SetCurrentUserTag
		$a_01_21 = {44 61 72 74 5f 53 65 74 44 61 72 74 4c 69 62 72 61 72 79 53 6f 75 72 63 65 73 4b 65 72 6e 65 6c } //1 Dart_SetDartLibrarySourcesKernel
		$a_01_22 = {44 61 72 74 5f 53 65 74 44 65 66 65 72 72 65 64 4c 6f 61 64 48 61 6e 64 6c 65 72 } //1 Dart_SetDeferredLoadHandler
		$a_01_23 = {44 61 72 74 5f 53 65 74 44 6f 75 62 6c 65 52 65 74 75 72 6e 56 61 6c 75 65 } //1 Dart_SetDoubleReturnValue
		$a_01_24 = {44 61 72 74 5f 53 65 74 44 77 61 72 66 53 74 61 63 6b 54 72 61 63 65 46 6f 6f 74 6e 6f 74 65 43 61 6c 6c 62 61 63 6b } //1 Dart_SetDwarfStackTraceFootnoteCallback
		$a_01_25 = {44 61 72 74 5f 53 65 74 45 6d 62 65 64 64 65 72 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 61 6c 6c 62 61 63 6b } //1 Dart_SetEmbedderInformationCallback
		$a_01_26 = {44 61 72 74 5f 53 65 74 45 6e 61 62 6c 65 64 54 69 6d 65 6c 69 6e 65 43 61 74 65 67 6f 72 79 } //1 Dart_SetEnabledTimelineCategory
		$a_01_27 = {44 61 72 74 5f 53 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 43 61 6c 6c 62 61 63 6b } //1 Dart_SetEnvironmentCallback
		$a_01_28 = {44 61 72 74 5f 53 65 74 46 66 69 4e 61 74 69 76 65 52 65 73 6f 6c 76 65 72 } //1 Dart_SetFfiNativeResolver
		$a_01_29 = {44 61 72 74 5f 53 65 74 46 69 6c 65 4d 6f 64 69 66 69 65 64 43 61 6c 6c 62 61 63 6b } //1 Dart_SetFileModifiedCallback
		$a_01_30 = {44 61 72 74 5f 53 65 74 48 65 61 70 53 61 6d 70 6c 69 6e 67 50 65 72 69 6f 64 } //1 Dart_SetHeapSamplingPeriod
		$a_01_31 = {44 61 72 74 5f 53 65 74 49 6e 74 65 67 65 72 52 65 74 75 72 6e 56 61 6c 75 65 } //1 Dart_SetIntegerReturnValue
		$a_01_32 = {44 61 72 74 5f 53 65 74 4c 69 62 72 61 72 79 54 61 67 48 61 6e 64 6c 65 72 } //1 Dart_SetLibraryTagHandler
		$a_01_33 = {44 61 72 74 5f 53 65 74 4d 65 73 73 61 67 65 4e 6f 74 69 66 79 43 61 6c 6c 62 61 63 6b } //1 Dart_SetMessageNotifyCallback
		$a_01_34 = {44 61 72 74 5f 53 65 74 4e 61 74 69 76 65 49 6e 73 74 61 6e 63 65 46 69 65 6c 64 } //1 Dart_SetNativeInstanceField
		$a_01_35 = {44 61 72 74 5f 53 65 74 4e 61 74 69 76 65 52 65 73 6f 6c 76 65 72 } //1 Dart_SetNativeResolver
		$a_01_36 = {44 61 72 74 5f 53 65 74 50 61 75 73 65 64 4f 6e 45 78 69 74 } //1 Dart_SetPausedOnExit
		$a_01_37 = {44 61 72 74 5f 53 65 74 50 61 75 73 65 64 4f 6e 53 74 61 72 74 } //1 Dart_SetPausedOnStart
		$a_01_38 = {44 61 72 74 5f 53 65 74 50 65 72 66 6f 72 6d 61 6e 63 65 4d 6f 64 65 } //1 Dart_SetPerformanceMode
		$a_01_39 = {44 61 72 74 5f 53 65 74 50 65 72 73 69 73 74 65 6e 74 48 61 6e 64 6c 65 } //1 Dart_SetPersistentHandle
		$a_01_40 = {44 61 72 74 5f 53 65 74 52 65 74 75 72 6e 56 61 6c 75 65 } //1 Dart_SetReturnValue
		$a_01_41 = {44 61 72 74 5f 53 65 74 52 6f 6f 74 4c 69 62 72 61 72 79 } //1 Dart_SetRootLibrary
		$a_01_42 = {44 61 72 74 5f 53 65 74 53 65 72 76 69 63 65 53 74 72 65 61 6d 43 61 6c 6c 62 61 63 6b 73 } //1 Dart_SetServiceStreamCallbacks
		$a_01_43 = {44 61 72 74 5f 53 65 74 53 68 6f 75 6c 64 50 61 75 73 65 4f 6e 45 78 69 74 } //1 Dart_SetShouldPauseOnExit
		$a_01_44 = {44 61 72 74 5f 53 65 74 53 68 6f 75 6c 64 50 61 75 73 65 4f 6e 53 74 61 72 74 } //1 Dart_SetShouldPauseOnStart
		$a_01_45 = {44 61 72 74 5f 53 65 74 53 74 69 63 6b 79 45 72 72 6f 72 } //1 Dart_SetStickyError
		$a_01_46 = {44 61 72 74 5f 53 65 74 54 68 72 65 61 64 4e 61 6d 65 } //1 Dart_SetThreadName
		$a_01_47 = {44 61 72 74 5f 53 65 74 54 69 6d 65 6c 69 6e 65 52 65 63 6f 72 64 65 72 43 61 6c 6c 62 61 63 6b } //1 Dart_SetTimelineRecorderCallback
		$a_01_48 = {44 61 72 74 5f 53 65 74 56 4d 46 6c 61 67 73 } //1 Dart_SetVMFlags
		$a_01_49 = {44 61 72 74 5f 53 65 74 57 65 61 6b 48 61 6e 64 6c 65 52 65 74 75 72 6e 56 61 6c 75 65 } //1 Dart_SetWeakHandleReturnValue
		$a_01_50 = {44 61 72 74 5f 53 68 6f 75 6c 64 50 61 75 73 65 4f 6e 45 78 69 74 } //1 Dart_ShouldPauseOnExit
		$a_01_51 = {44 61 72 74 5f 53 68 6f 75 6c 64 50 61 75 73 65 4f 6e 53 74 61 72 74 } //1 Dart_ShouldPauseOnStart
		$a_01_52 = {44 61 72 74 5f 53 68 75 74 64 6f 77 6e 49 73 6f 6c 61 74 65 } //1 Dart_ShutdownIsolate
		$a_01_53 = {44 61 72 74 5f 53 6f 72 74 43 6c 61 73 73 65 73 } //1 Dart_SortClasses
		$a_01_54 = {44 61 72 74 5f 53 74 61 72 74 50 72 6f 66 69 6c 69 6e 67 } //1 Dart_StartProfiling
		$a_01_55 = {44 61 72 74 5f 53 74 6f 70 50 72 6f 66 69 6c 69 6e 67 } //1 Dart_StopProfiling
		$a_01_56 = {44 61 72 74 5f 53 74 72 69 6e 67 47 65 74 50 72 6f 70 65 72 74 69 65 73 } //1 Dart_StringGetProperties
		$a_01_57 = {44 61 72 74 5f 53 74 72 69 6e 67 4c 65 6e 67 74 68 } //1 Dart_StringLength
		$a_01_58 = {44 61 72 74 5f 53 74 72 69 6e 67 53 74 6f 72 61 67 65 53 69 7a 65 } //1 Dart_StringStorageSize
		$a_01_59 = {44 61 72 74 5f 53 74 72 69 6e 67 54 6f 43 53 74 72 69 6e 67 } //1 Dart_StringToCString
		$a_01_60 = {44 61 72 74 5f 53 74 72 69 6e 67 54 6f 4c 61 74 69 6e 31 } //1 Dart_StringToLatin1
		$a_01_61 = {44 61 72 74 5f 53 74 72 69 6e 67 54 6f 55 54 46 31 36 } //1 Dart_StringToUTF16
		$a_01_62 = {44 61 72 74 5f 53 74 72 69 6e 67 54 6f 55 54 46 38 } //1 Dart_StringToUTF8
		$a_01_63 = {44 61 72 74 5f 54 68 72 65 61 64 44 69 73 61 62 6c 65 50 72 6f 66 69 6c 69 6e 67 } //1 Dart_ThreadDisableProfiling
		$a_01_64 = {44 61 72 74 5f 54 68 72 65 61 64 45 6e 61 62 6c 65 50 72 6f 66 69 6c 69 6e 67 } //1 Dart_ThreadEnableProfiling
		$a_01_65 = {44 61 72 74 5f 54 79 70 65 64 44 61 74 61 41 63 71 75 69 72 65 44 61 74 61 } //1 Dart_TypedDataAcquireData
		$a_01_66 = {44 61 72 74 5f 54 79 70 65 64 44 61 74 61 52 65 6c 65 61 73 65 44 61 74 61 } //1 Dart_TypedDataReleaseData
		$a_01_67 = {44 61 72 74 5f 55 70 64 61 74 65 45 78 74 65 72 6e 61 6c 53 69 7a 65 } //1 Dart_UpdateExternalSize
		$a_01_68 = {44 61 72 74 5f 55 70 64 61 74 65 46 69 6e 61 6c 69 7a 61 62 6c 65 45 78 74 65 72 6e 61 6c 53 69 7a 65 } //1 Dart_UpdateFinalizableExternalSize
		$a_01_69 = {44 61 72 74 5f 56 65 72 73 69 6f 6e 53 74 72 69 6e 67 } //1 Dart_VersionString
		$a_01_70 = {44 61 72 74 5f 57 61 69 74 46 6f 72 45 76 65 6e 74 } //1 Dart_WaitForEvent
		$a_01_71 = {44 61 72 74 5f 57 72 69 74 65 48 65 61 70 53 6e 61 70 73 68 6f 74 } //1 Dart_WriteHeapSnapshot
		$a_01_72 = {44 61 72 74 5f 57 72 69 74 65 50 72 6f 66 69 6c 65 54 6f 54 69 6d 65 6c 69 6e 65 } //1 Dart_WriteProfileToTimeline
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1+(#a_01_39  & 1)*1+(#a_01_40  & 1)*1+(#a_01_41  & 1)*1+(#a_01_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_01_45  & 1)*1+(#a_01_46  & 1)*1+(#a_01_47  & 1)*1+(#a_01_48  & 1)*1+(#a_01_49  & 1)*1+(#a_01_50  & 1)*1+(#a_01_51  & 1)*1+(#a_01_52  & 1)*1+(#a_01_53  & 1)*1+(#a_01_54  & 1)*1+(#a_01_55  & 1)*1+(#a_01_56  & 1)*1+(#a_01_57  & 1)*1+(#a_01_58  & 1)*1+(#a_01_59  & 1)*1+(#a_01_60  & 1)*1+(#a_01_61  & 1)*1+(#a_01_62  & 1)*1+(#a_01_63  & 1)*1+(#a_01_64  & 1)*1+(#a_01_65  & 1)*1+(#a_01_66  & 1)*1+(#a_01_67  & 1)*1+(#a_01_68  & 1)*1+(#a_01_69  & 1)*1+(#a_01_70  & 1)*1+(#a_01_71  & 1)*1+(#a_01_72  & 1)*1) >=10
 
}
rule _#do_exhaustivehstr_64bit_rescan_56{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 44 69 73 61 62 6c 65 5f 57 69 6e 64 6f 77 73 75 70 64 61 74 65 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_57{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 4d 00 69 00 63 00 54 00 72 00 61 00 79 00 2e 00 6c 00 6f 00 67 00 } //1 c:\users\Public\MicTray.log
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_58{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 00 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 54 00 68 00 75 00 6d 00 62 00 73 00 43 00 61 00 63 00 68 00 65 00 2e 00 64 00 62 00 } //1 %LOCALAPPDATA%\ThumbsCache.db
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_64bit_rescan_59{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 00 75 00 74 00 74 00 79 00 43 00 6f 00 6e 00 66 00 69 00 67 00 42 00 6f 00 78 00 } //1 PuttyConfigBox
		$a_01_1 = {53 00 75 00 6d 00 61 00 74 00 72 00 61 00 50 00 44 00 46 00 } //1 SumatraPDF
		$a_01_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 rundll32.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_64bit_rescan_60{
	meta:
		description = "!#do_exhaustivehstr_64bit_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 43 61 6e 6e 6f 74 20 63 61 6c 6c 20 63 6f 6e 6e 65 63 74 20 6f 6e 20 55 4e 42 4f 55 4e 44 20 73 6f 63 6b 65 74 20 69 6e 20 72 65 6e 64 65 7a 76 6f 75 73 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 65 74 75 70 00 } //1
		$a_01_1 = {00 4c 69 73 74 65 6e 2f 61 63 63 65 70 74 20 69 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 69 6e 20 72 65 6e 64 65 7a 6f 75 73 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 65 74 75 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}