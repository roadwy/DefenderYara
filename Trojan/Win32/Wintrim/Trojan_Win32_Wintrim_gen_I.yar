
rule Trojan_Win32_Wintrim_gen_I{
	meta:
		description = "Trojan:Win32/Wintrim.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 19 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 54 72 75 73 74 5c 54 72 75 73 74 20 50 72 6f 76 69 64 65 72 73 5c 53 6f 66 74 77 61 72 65 20 50 75 62 6c 69 73 68 69 6e 67 5c 54 72 75 73 74 20 44 61 74 61 62 61 73 65 5c 30 } //1 Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\Trust Database\0
		$a_00_1 = {65 6c 65 63 74 72 6f 6e 69 63 2d 67 72 6f 75 70 } //5 electronic-group
		$a_00_2 = {55 4e 4c 49 4d 49 54 45 44 20 41 43 43 45 53 53 20 54 4f 20 4f 55 52 20 4e 45 54 57 4f 52 4b } //5 UNLIMITED ACCESS TO OUR NETWORK
		$a_01_3 = {5c 49 6e 73 74 61 6e 74 20 41 63 63 65 73 73 5c 43 65 6e 74 65 72 5c } //4 \Instant Access\Center\
		$a_01_4 = {4f 70 65 6e 41 63 63 65 73 73 } //1 OpenAccess
		$a_01_5 = {41 75 74 6f 64 69 61 6c 44 6c 6c 4e 61 6d 65 33 32 } //1 AutodialDllName32
		$a_01_6 = {45 47 44 41 43 43 45 53 53 5f 41 53 50 49 } //8 EGDACCESS_ASPI
		$a_01_7 = {53 65 74 46 72 6f 6d 4d 61 6a 52 65 6d } //4 SetFromMajRem
		$a_01_8 = {53 65 74 44 69 61 6c 65 72 4f 66 66 6c 69 6e 65 4d 6f 64 65 } //4 SetDialerOfflineMode
		$a_01_9 = {69 6e 73 74 61 6e 74 20 61 63 63 65 73 73 2e 65 78 65 } //3 instant access.exe
		$a_01_10 = {5c 64 69 61 6c 65 72 65 78 65 2e 69 6e 69 } //4 \dialerexe.ini
		$a_01_11 = {4e 4f 43 52 45 44 49 54 43 41 52 44 } //4 NOCREDITCARD
		$a_01_12 = {53 6f 66 74 77 61 72 65 5c 45 47 44 48 54 4d 4c } //3 Software\EGDHTML
		$a_01_13 = {52 61 73 47 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasGetEntryPropertiesA
		$a_01_14 = {49 41 5f 41 63 74 69 6f 6e } //4 IA_Action
		$a_01_15 = {41 4f 4c 20 46 72 61 6d 65 32 35 } //2 AOL Frame25
		$a_01_16 = {41 4f 4c 5c 43 5f 41 4f 4c 20 39 2e 30 } //2 AOL\C_AOL 9.0
		$a_01_17 = {5c 73 74 61 74 75 73 2e 69 6e 69 } //1 \status.ini
		$a_01_18 = {4e 6f 72 77 65 67 69 61 6e 2d 4e 79 6e 6f 72 73 6b } //1 Norwegian-Nynorsk
		$a_01_19 = {65 6e 67 6c 69 73 68 2d 74 72 69 6e 69 64 61 64 20 79 20 74 6f 62 61 67 6f } //1 english-trinidad y tobago
		$a_01_20 = {6e 6f 72 77 65 67 69 61 6e 2d 6e 79 6e 6f 72 73 6b } //1 norwegian-nynorsk
		$a_01_21 = {7b 33 31 44 44 43 31 46 44 2d 43 45 41 33 2d 34 38 33 37 2d 41 36 44 43 2d 38 37 45 36 37 30 31 35 41 44 43 39 7d } //4 {31DDC1FD-CEA3-4837-A6DC-87E67015ADC9}
		$a_01_22 = {7b 34 38 36 45 34 38 42 35 2d 41 42 46 32 2d 34 32 42 42 2d 41 33 32 37 2d 32 36 37 39 44 46 33 46 42 38 32 32 7d } //4 {486E48B5-ABF2-42BB-A327-2679DF3FB822}
		$a_01_23 = {7b 43 36 37 36 30 41 30 37 2d 41 35 37 34 2d 34 37 30 35 2d 42 31 31 33 2d 37 38 35 36 33 31 35 39 32 32 43 33 7d } //4 {C6760A07-A574-4705-B113-7856315922C3}
		$a_01_24 = {4e 61 76 69 6c 6f 67 31 } //-100 Navilog1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*8+(#a_01_7  & 1)*4+(#a_01_8  & 1)*4+(#a_01_9  & 1)*3+(#a_01_10  & 1)*4+(#a_01_11  & 1)*4+(#a_01_12  & 1)*3+(#a_01_13  & 1)*1+(#a_01_14  & 1)*4+(#a_01_15  & 1)*2+(#a_01_16  & 1)*2+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*4+(#a_01_22  & 1)*4+(#a_01_23  & 1)*4+(#a_01_24  & 1)*-100) >=19
 
}