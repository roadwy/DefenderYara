
rule Trojan_Win32_RootkitDrv_AMTB{
	meta:
		description = "Trojan:Win32/RootkitDrv!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {5c 72 37 37 2d 78 36 34 2e 70 64 62 } //\r77-x64.pdb  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 61 73 6f 6e 57 69 7a 4e 6f 6e } //SOFTWARE\MasonWizNon  1
		$a_80_2 = {2d 72 6f 6f 74 6b 69 74 2d 6d 61 73 74 65 72 } //-rootkit-master  1
		$a_80_3 = {5c 6e 33 72 2d } //\n3r-  1
		$a_80_4 = {72 37 37 2d 78 36 34 2e 64 6c 6c } //r77-x64.dll  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}
rule Trojan_Win32_RootkitDrv_AMTB_2{
	meta:
		description = "Trojan:Win32/RootkitDrv!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {6c 69 73 74 68 2e 64 61 74 } //listh.dat  1
		$a_80_1 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 58 47 72 65 65 6e 58 } //\DosDevices\XGreenX  1
		$a_80_2 = {74 2e 5c 44 65 76 69 63 65 5c 50 6f 77 65 72 43 68 61 6e 67 65 } //t.\Device\PowerChange  1
		$a_80_3 = {43 3a 5c 42 41 54 2e 52 41 52 } //C:\BAT.RAR  1
		$a_80_4 = {69 3a 5c 70 72 6f 6a 65 63 74 5c 77 67 5c 63 6f 64 65 5c 64 72 69 76 65 72 73 5c 64 72 69 76 65 72 63 5c 77 69 6e 64 6f 77 73 5f 6d 6f 64 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 55 70 64 61 74 61 43 57 69 6e 58 50 78 38 36 2e 70 64 62 } //i:\project\wg\code\drivers\driverc\windows_mod\objfre_wxp_x86\i386\UpdataCWinXPx86.pdb  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}