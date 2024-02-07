
rule PWS_Win32_Progent_B_dll{
	meta:
		description = "PWS:Win32/Progent.B!dll,SIGNATURE_TYPE_PEHSTR,ffffff82 00 64 00 44 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 71 73 65 72 76 69 63 65 2e 65 78 65 } //01 00  \qservice.exe
		$a_01_1 = {5c 61 67 6e 74 5f 66 70 73 2e 65 78 65 } //01 00  \agnt_fps.exe
		$a_01_2 = {5c 61 67 6e 74 5f 66 70 73 2e 64 61 74 } //01 00  \agnt_fps.dat
		$a_01_3 = {5c 48 6f 6f 6b 4d 70 69 2e 64 6c 6c } //01 00  \HookMpi.dll
		$a_01_4 = {5c 61 67 6e 74 5f 6d 70 73 2e 65 78 65 } //01 00  \agnt_mps.exe
		$a_01_5 = {5c 61 67 6e 74 5f 6d 70 73 2e 64 61 74 } //01 00  \agnt_mps.dat
		$a_01_6 = {5c 61 67 6e 74 5f 70 6e 63 2e 65 78 65 } //01 00  \agnt_pnc.exe
		$a_01_7 = {5c 5f 70 6e 63 2e 64 61 74 } //01 00  \_pnc.dat
		$a_01_8 = {5c 61 67 6e 74 5f 6d 73 6e 2e 65 78 65 } //01 00  \agnt_msn.exe
		$a_01_9 = {5c 61 67 6e 74 5f 6d 73 6e 2e 64 61 74 } //01 00  \agnt_msn.dat
		$a_01_10 = {5c 73 65 72 76 69 63 65 73 2e 64 6c 6c } //01 00  \services.dll
		$a_01_11 = {5c 64 72 69 76 65 72 73 5c 48 69 64 65 4d 65 2e 73 79 73 } //01 00  \drivers\HideMe.sys
		$a_01_12 = {5c 6d 73 64 69 72 65 63 74 78 2e 73 79 73 } //01 00  \msdirectx.sys
		$a_01_13 = {5c 6b 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00  \kurlmon.dll
		$a_01_14 = {5c 6d 73 65 68 6b 2e 64 6c 6c } //01 00  \msehk.dll
		$a_01_15 = {5c 62 73 7a 69 70 2e 64 6c 6c } //01 00  \bszip.dll
		$a_01_16 = {5c 77 69 6e 73 33 32 2e 7a 69 70 } //01 00  \wins32.zip
		$a_01_17 = {5c 46 69 6c 65 5a 69 6c 6c 61 2e 78 6d 6c } //01 00  \FileZilla.xml
		$a_01_18 = {6d 63 76 73 65 73 63 6e 2e 65 78 65 } //01 00  mcvsescn.exe
		$a_01_19 = {5c 77 69 6e 73 33 32 5c } //01 00  \wins32\
		$a_01_20 = {5c 6b 5f 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00  \k_urlmon.dll
		$a_01_21 = {71 73 65 72 76 69 63 65 73 } //01 00  qservices
		$a_01_22 = {68 6f 6f 6b 64 6c 6c } //01 00  hookdll
		$a_01_23 = {48 5f 6f 5f 6f 5f 6b } //01 00  H_o_o_k
		$a_01_24 = {55 6e 68 5f 6f 5f 6f 5f 6b } //01 00  Unh_o_o_k
		$a_01_25 = {6d 61 69 6c 70 76 } //01 00  mailpv
		$a_01_26 = {50 69 6e 63 68 } //05 00  Pinch
		$a_01_27 = {43 61 6e 27 74 20 64 65 64 65 63 74 } //05 00  Can't dedect
		$a_01_28 = {48 69 20 63 72 69 6d 69 6e 61 6c 20 3d 29 } //05 00  Hi criminal =)
		$a_01_29 = {4e 6f 20 6d 6f 72 65 20 4d 61 69 6c 20 53 63 61 6e 6e 69 6e 67 20 3d 29 } //05 00  No more Mail Scanning =)
		$a_01_30 = {4e 6f 20 6d 6f 72 65 20 46 69 72 65 77 61 6c 6c 20 50 72 6f 74 65 63 74 69 6f 6e 20 3d 29 } //05 00  No more Firewall Protection =)
		$a_01_31 = {6d 6f 75 73 65 68 6f 6f 6b } //05 00  mousehook
		$a_01_32 = {48 6f 6f 6b 42 61 73 6c 61 74 } //03 00  HookBaslat
		$a_01_33 = {43 6f 6d 70 75 74 65 72 20 4e 61 6d 65 20 20 20 20 3a 20 } //03 00  Computer Name    : 
		$a_01_34 = {55 73 65 72 20 4e 61 6d 65 20 20 20 20 20 20 20 20 3a 20 } //03 00  User Name        : 
		$a_01_35 = {50 72 6f 64 75 63 74 49 64 20 20 20 20 20 20 20 20 3a 20 } //03 00  ProductId        : 
		$a_01_36 = {49 2e 45 78 70 6c 6f 72 65 72 20 56 65 72 20 20 20 3a 20 } //03 00  I.Explorer Ver   : 
		$a_01_37 = {56 65 6e 64 6f 72 20 49 64 65 6e 74 69 66 69 65 72 3a 20 } //03 00  Vendor Identifier: 
		$a_01_38 = {48 61 72 64 20 44 72 69 76 65 28 73 29 20 4c 69 73 74 3a } //03 00  Hard Drive(s) List:
		$a_01_39 = {50 72 6f 41 67 65 6e 74 20 3a 20 5b } //03 00  ProAgent : [
		$a_01_40 = {44 69 73 70 6c 61 79 20 41 64 61 70 74 65 72 28 73 29 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //03 00  Display Adapter(s) Information:
		$a_01_41 = {53 6f 75 6e 64 20 43 61 72 64 28 73 29 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //03 00  Sound Card(s) Information:
		$a_01_42 = {46 74 70 20 53 65 72 76 65 72 3a 20 } //03 00  Ftp Server: 
		$a_01_43 = {50 45 45 52 20 46 54 50 20 50 41 53 53 57 4f 52 44 53 } //03 00  PEER FTP PASSWORDS
		$a_01_44 = {45 58 45 45 4d 20 50 41 53 53 57 4f 52 44 53 } //03 00  EXEEM PASSWORDS
		$a_01_45 = {53 45 4e 44 4c 49 4e 4b 20 50 41 53 53 57 4f 52 44 53 } //03 00  SENDLINK PASSWORDS
		$a_01_46 = {43 48 41 54 20 41 4e 59 57 48 45 52 45 20 50 41 53 53 57 4f 52 44 53 } //03 00  CHAT ANYWHERE PASSWORDS
		$a_01_47 = {46 54 50 4e 4f 57 20 50 41 53 53 57 4f 52 44 53 } //03 00  FTPNOW PASSWORDS
		$a_01_48 = {44 45 4c 55 58 45 20 46 54 50 20 50 41 53 53 57 4f 52 44 53 } //03 00  DELUXE FTP PASSWORDS
		$a_01_49 = {44 45 4c 55 58 45 20 46 54 50 20 50 52 4f 20 50 41 53 53 57 4f 52 44 53 } //03 00  DELUXE FTP PRO PASSWORDS
		$a_01_50 = {4d 4f 52 50 48 45 55 53 20 43 48 41 54 20 50 41 53 53 57 4f 52 44 53 } //03 00  MORPHEUS CHAT PASSWORDS
		$a_01_51 = {42 49 54 43 4f 4d 45 54 20 50 41 53 53 57 4f 52 44 53 } //03 00  BITCOMET PASSWORDS
		$a_01_52 = {46 49 52 45 46 4c 59 20 50 41 53 53 57 4f 52 44 53 } //03 00  FIREFLY PASSWORDS
		$a_01_53 = {4b 45 59 4c 4f 47 47 45 52 20 52 45 43 4f 52 44 53 } //03 00  KEYLOGGER RECORDS
		$a_01_54 = {55 52 4c 20 48 49 53 54 4f 52 59 } //03 00  URL HISTORY
		$a_01_55 = {50 52 4f 43 45 53 53 45 53 20 49 4e 46 4f 52 4d 41 54 49 4f 4e } //03 00  PROCESSES INFORMATION
		$a_01_56 = {50 43 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 53 } //03 00  PC INFORMATIONS
		$a_01_57 = {43 55 54 45 20 46 54 50 20 50 41 53 53 57 4f 52 44 53 } //03 00  CUTE FTP PASSWORDS
		$a_01_58 = {46 4c 41 53 48 20 46 58 50 20 50 41 53 53 57 4f 52 44 53 } //03 00  FLASH FXP PASSWORDS
		$a_01_59 = {57 53 5f 46 54 50 20 50 41 53 53 57 4f 52 44 53 } //03 00  WS_FTP PASSWORDS
		$a_01_60 = {46 49 4c 45 5a 49 4c 4c 41 20 50 41 53 53 57 4f 52 44 53 } //03 00  FILEZILLA PASSWORDS
		$a_01_61 = {43 44 2d 4b 45 59 53 } //03 00  CD-KEYS
		$a_01_62 = {41 44 44 52 45 53 53 20 42 4f 4f 4b 20 52 45 43 4f 52 44 53 } //03 00  ADDRESS BOOK RECORDS
		$a_01_63 = {49 4e 53 54 41 4e 54 20 4d 45 53 53 45 4e 47 45 52 20 50 41 53 53 57 4f 52 44 53 } //03 00  INSTANT MESSENGER PASSWORDS
		$a_01_64 = {4d 41 49 4c 20 50 41 53 53 57 4f 52 44 53 } //03 00  MAIL PASSWORDS
		$a_01_65 = {43 52 59 50 54 45 44 20 44 41 54 41 } //03 00  CRYPTED DATA
		$a_01_66 = {50 52 4f 54 45 43 54 45 44 20 53 54 4f 52 41 47 45 } //03 00  PROTECTED STORAGE
		$a_01_67 = {4e 6f 74 20 52 65 63 6f 72 64 65 64 21 } //00 00  Not Recorded!
	condition:
		any of ($a_*)
 
}