
rule Spyware_Win32_CnsMin{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 43 6e 73 4d 69 6e 4b 50 } //2 \\.\Global\CnsMinKP
		$a_01_1 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 56 78 64 } //2 \\.\CnsMinKP.Vxd
		$a_01_2 = {25 73 63 6e 73 64 74 75 2e 63 61 62 } //4 %scnsdtu.cab
		$a_01_3 = {25 73 33 37 32 31 5c 63 6e 73 31 2e 64 61 74 } //3 %s3721\cns1.dat
		$a_01_4 = {25 73 63 6e 73 2e 64 61 74 } //1 %scns.dat
		$a_01_5 = {63 6e 73 31 75 2e 63 70 72 } //1 cns1u.cpr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}
rule Spyware_Win32_CnsMin_2{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 } //1 Software\3721\Cns
		$a_00_1 = {33 37 32 31 48 65 6c 70 65 72 5f 43 4e 53 } //1 3721Helper_CNS
		$a_00_2 = {43 4e 53 48 65 6c 70 65 72 4d 75 74 65 78 } //1 CNSHelperMutex
		$a_02_3 = {53 74 61 72 74 52 65 66 65 72 65 72 [0-04] 61 6c 72 65 78 2e 64 6c 6c } //1
		$a_00_4 = {41 75 74 6f 4c 69 76 65 5c 61 6c 72 65 78 } //1 AutoLive\alrex
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule Spyware_Win32_CnsMin_3{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 38 39 36 35 37 4d 55 54 45 58 5f 52 45 4d 4f 54 45 } //2 K89657MUTEX_REMOTE
		$a_01_1 = {37 35 30 34 38 37 30 30 2d 45 46 31 46 2d 31 31 44 30 2d 39 38 38 38 2d 30 30 36 30 39 37 44 45 41 43 46 39 7d 5c 43 6f 75 6e 74 5c 48 52 5a 52 5f 45 48 41 43 } //2 75048700-EF1F-11D0-9888-006097DEACF9}\Count\HRZR_EHAC
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2e 33 37 32 31 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 } //2 download.3721.com/download
		$a_01_3 = {43 64 6e 43 6c 69 65 6e 74 } //1 CdnClient
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule Spyware_Win32_CnsMin_4{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6e 73 69 6e 73 74 68 6c 70 65 72 2e 64 6c 6c 00 66 75 6e 63 } //1
		$a_02_1 = {77 69 6e 69 6e 69 74 2e 69 6e 69 00 5c [0-04] 44 4f 57 4e 4c 4f 7e 31 5c 43 4e 53 00 } //1
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 } //1 SYSTEM\CurrentControlSet\Control\Session Manager
		$a_00_3 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 PendingFileRenameOperations
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Spyware_Win32_CnsMin_5{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 76 78 64 } //3 \\.\CnsMinKP.vxd
		$a_01_1 = {69 64 6e 6d 61 69 6c 2e 65 78 65 } //1 idnmail.exe
		$a_01_2 = {63 6e 6e 69 63 } //1 cnnic
		$a_01_3 = {62 64 62 61 72 2e 65 78 65 } //1 bdbar.exe
		$a_01_4 = {73 65 74 75 70 5f 62 64 2e 65 78 65 } //1 setup_bd.exe
		$a_01_5 = {68 6a 62 61 72 2e 65 78 65 } //1 hjbar.exe
		$a_01_6 = {43 4c 53 49 44 5c 7b 42 42 39 33 36 33 32 33 2d 31 39 46 41 2d 34 35 32 31 2d 42 41 32 39 2d 45 43 41 36 41 31 32 31 42 43 37 38 7d } //3 CLSID\{BB936323-19FA-4521-BA29-ECA6A121BC78}
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 43 4e 52 45 44 49 52 45 43 54 } //3 Software\CNREDIRECT
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3) >=10
 
}
rule Spyware_Win32_CnsMin_6{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 6e 73 69 6f 2e 64 6c 6c } //2 cnsio.dll
		$a_01_1 = {41 64 64 43 68 69 6e 41 64 64 72 } //1 AddChinAddr
		$a_01_2 = {44 65 6c 43 68 69 6e 41 64 64 72 } //1 DelChinAddr
		$a_01_3 = {53 65 74 53 77 69 74 63 68 } //1 SetSwitch
		$a_01_4 = {43 6e 73 4d 69 6e 43 68 69 6e 41 64 64 72 41 75 74 6f 43 6f 6d 70 6c 65 74 65 4d 75 74 65 78 } //3 CnsMinChinAddrAutoCompleteMutex
		$a_01_5 = {63 6e 73 5f 74 65 6d 70 2f } //2 cns_temp/
		$a_01_6 = {63 6e 73 5f 74 65 6d 70 5c } //2 cns_temp\
		$a_01_7 = {43 6e 73 4d 69 6e 41 75 74 6f 43 6f 6d 70 6c 65 74 65 46 4d 61 70 53 74 72 } //3 CnsMinAutoCompleteFMapStr
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 55 72 6c } //5 Software\3721\CnsUrl
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e } //5 Software\3721\CnsMin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*3+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=23
 
}
rule Spyware_Win32_CnsMin_7{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 43 6e 73 4d 69 6e 4b 50 } //2 \\.\Global\CnsMinKP
		$a_01_1 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 56 78 64 } //2 \\.\CnsMinKP.Vxd
		$a_01_2 = {43 6e 73 4d 69 6e 44 54 2e 64 6c 6c } //2 CnsMinDT.dll
		$a_01_3 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //2 System\CurrentControlSet\Services\CnsMinKP
		$a_01_4 = {7b 43 32 32 44 36 44 34 30 2d 34 37 44 38 2d 34 30 66 65 2d 38 32 35 41 2d 43 43 37 46 34 44 38 38 42 33 42 38 7d } //2 {C22D6D40-47D8-40fe-825A-CC7F4D88B3B8}
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e 5c 56 61 72 69 61 6e 74 } //2 Software\3721\CnsMin\Variant
		$a_01_6 = {43 4e 53 43 46 47 46 2e 44 41 54 } //1 CNSCFGF.DAT
		$a_01_7 = {43 4e 53 4d 49 4e 2e 44 41 54 } //1 CNSMIN.DAT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}
rule Spyware_Win32_CnsMin_8{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 6e 73 68 69 6e 74 2e 64 6c 6c } //2 cnshint.dll
		$a_01_1 = {5c 43 6e 73 4d 69 6e 49 4f 2e 64 6c 6c } //2 \CnsMinIO.dll
		$a_01_2 = {43 4c 53 49 44 5c 7b 42 38 33 46 43 32 37 33 2d 33 35 32 32 2d 34 43 43 36 2d 39 32 45 43 2d 37 35 43 43 38 36 36 37 38 44 41 34 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //2 CLSID\{B83FC273-3522-4CC6-92EC-75CC86678DA4}\InprocServer32
		$a_01_3 = {33 37 32 31 43 6e 73 42 61 72 50 72 6f 70 } //2 3721CnsBarProp
		$a_01_4 = {43 6e 73 54 69 70 73 } //2 CnsTips
		$a_01_5 = {43 4e 53 43 6f 6c 6c 65 63 74 } //2 CNSCollect
		$a_01_6 = {63 6e 73 70 6c 75 73 2e 64 6c 6c } //2 cnsplus.dll
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 21 43 4e 53 } //2 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\!CNS
		$a_01_8 = {68 74 74 70 3a 2f 2f 63 6e 73 2e 33 37 32 31 2e 63 6f 6d 2f 63 6e 73 2e 64 6c 6c 3f } //2 http://cns.3721.com/cns.dll?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=14
 
}
rule Spyware_Win32_CnsMin_9{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 43 6e 73 4d 69 6e 4b 50 } //2 \\.\Global\CnsMinKP
		$a_01_1 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 56 78 64 } //2 \\.\CnsMinKP.Vxd
		$a_01_2 = {43 6e 73 4d 69 6e 45 78 2e 64 6c 6c } //1 CnsMinEx.dll
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e } //1 Software\3721\CnsMin
		$a_01_4 = {68 74 74 70 3a 2f 2f 73 65 65 6b 2e 33 37 32 31 2e 63 6f 6d 2f 73 72 63 68 61 73 73 74 2e 68 74 6d } //2 http://seek.3721.com/srchasst.htm
		$a_01_5 = {5c 63 6e 73 2e 64 6c 6c } //1 \cns.dll
		$a_01_6 = {5c 63 6e 73 2e 65 78 65 } //1 \cns.exe
		$a_01_7 = {43 6e 73 4d 69 6e 48 4b 2e 43 6e 73 48 6f 6f 6b 2e 31 } //1 CnsMinHK.CnsHook.1
		$a_01_8 = {43 4c 53 49 44 5c 7b 41 35 41 44 45 41 45 37 2d 41 38 42 34 2d 34 46 39 34 2d 39 31 32 38 2d 42 46 38 44 38 44 42 35 45 39 32 37 7d } //1 CLSID\{A5ADEAE7-A8B4-4F94-9128-BF8D8DB5E927}
		$a_01_9 = {43 6e 73 48 6f 6f 6b 2e 64 6c 6c } //1 CnsHook.dll
		$a_01_10 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 33 37 32 31 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 43 6e 73 4d 69 6e 45 78 4d 2e 69 6e 69 } //2 http://download.3721.com/download/CnsMinExM.ini
		$a_01_11 = {25 73 43 6e 73 4d 69 6e 53 65 2e 64 6c 6c } //2 %sCnsMinSe.dll
		$a_01_12 = {43 6e 73 4d 69 6e 55 70 2e 63 61 62 } //1 CnsMinUp.cab
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*1) >=14
 
}
rule Spyware_Win32_CnsMin_10{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 4e 53 53 65 61 72 63 68 } //2 CNSSearch
		$a_01_1 = {43 6e 73 4d 69 6e 43 67 2e 69 6e 69 } //2 CnsMinCg.ini
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 73 73 69 73 74 61 6e 74 2e 33 37 32 31 2e 63 6f 6d 2f 68 65 6c 70 2f 75 6e 69 6e 73 74 63 6e 73 2e 68 74 6d } //2 http://assistant.3721.com/help/uninstcns.htm
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 2e 33 37 32 31 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 63 6e 73 } //2 download.3721.com/download/cns
		$a_01_4 = {43 6e 73 48 6f 6f 6b 2e 64 6c 6c } //2 CnsHook.dll
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e 5c 43 6e 73 4d 69 6e 45 78 } //2 Software\3721\CnsMin\CnsMinEx
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 44 31 35 37 33 33 30 41 2d 39 45 46 33 2d 34 39 46 38 2d 39 41 36 37 2d 34 31 34 31 41 43 34 31 41 44 44 34 7d } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{D157330A-9EF3-49F8-9A67-4141AC41ADD4}
		$a_01_7 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //2 System\CurrentControlSet\Services\CnsMinKP
		$a_01_8 = {63 6e 73 6d 69 6e 2e 64 61 74 } //2 cnsmin.dat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=12
 
}
rule Spyware_Win32_CnsMin_11{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 "
		
	strings :
		$a_01_0 = {33 37 32 31 43 6e 73 42 61 72 50 72 6f 70 } //2 3721CnsBarProp
		$a_01_1 = {43 6e 73 48 69 6e 74 2e 64 6c 6c } //2 CnsHint.dll
		$a_01_2 = {43 4c 53 49 44 5c 7b 42 38 33 46 43 32 37 33 2d 33 35 32 32 2d 34 43 43 36 2d 39 32 45 43 2d 37 35 43 43 38 36 36 37 38 44 41 34 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //2 CLSID\{B83FC273-3522-4CC6-92EC-75CC86678DA4}\InprocServer32
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 41 73 73 69 73 74 5c 50 6c 75 67 69 6e 73 } //2 Software\3721\Assist\Plugins
		$a_01_4 = {25 73 2c 52 75 6e 53 65 74 74 69 6e 67 73 20 2d 72 65 70 61 69 72 69 65 } //1 %s,RunSettings -repairie
		$a_01_5 = {43 4e 53 45 6e 61 62 6c 65 } //2 CNSEnable
		$a_01_6 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //2 System\CurrentControlSet\Services\CnsMinKP
		$a_01_7 = {41 73 73 69 73 61 6e 74 53 68 61 72 65 } //1 AssisantShare
		$a_01_8 = {55 6e 69 6e 73 74 61 6c 6c 5c 7b 31 42 30 45 37 37 31 36 2d 38 39 38 45 2d 34 38 63 63 2d 39 36 39 30 2d 34 45 33 33 38 45 38 44 45 31 44 33 7d } //2 Uninstall\{1B0E7716-898E-48cc-9690-4E338E8DE1D3}
		$a_01_9 = {68 74 74 70 3a 2f 2f 63 6e 73 2e 33 37 32 31 2e 63 6f 6d 2f 63 6e 73 2e 64 6c 6c 3f } //2 http://cns.3721.com/cns.dll?
		$a_01_10 = {41 73 73 69 73 74 61 6e 74 52 65 67 69 73 74 65 72 55 73 65 72 4d 75 74 65 78 } //2 AssistantRegisterUserMutex
		$a_01_11 = {33 37 32 31 48 65 6c 70 65 72 5f 43 4e 53 } //2 3721Helper_CNS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=15
 
}
rule Spyware_Win32_CnsMin_12{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0e 00 00 "
		
	strings :
		$a_01_0 = {43 6e 73 4d 69 6e 2e 44 4c 4c } //2 CnsMin.DLL
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 49 6e 74 65 72 43 68 69 6e 61 5c 43 68 69 6e 40 64 64 72 65 73 73 } //2 software\InterChina\Chin@ddress
		$a_01_2 = {63 68 69 6e 61 64 64 72 6d 61 69 6e 6d 75 74 65 78 73 74 72 } //2 chinaddrmainmutexstr
		$a_01_3 = {68 74 74 70 3a 2f 2f 61 73 73 69 73 74 61 6e 74 2e 33 37 32 31 2e 63 6f 6d 2f 69 6e 73 74 6f 6b } //4 http://assistant.3721.com/instok
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e } //2 software\3721\CnsMin
		$a_01_5 = {61 73 73 69 73 74 63 6e 73 } //2 assistcns
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 33 37 32 31 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 43 6e 73 4d 69 6e 55 70 } //4 http://download.3721.com/download/CnsMinUp
		$a_01_7 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 56 78 64 } //2 \\.\CnsMinKP.Vxd
		$a_01_8 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //2 System\CurrentControlSet\Services\CnsMinKP
		$a_01_9 = {43 4c 53 49 44 5c 7b 37 43 41 38 33 43 46 31 2d 33 41 45 41 2d 34 32 44 30 2d 41 34 45 33 2d 31 35 39 34 46 43 36 45 34 38 42 32 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //2 CLSID\{7CA83CF1-3AEA-42D0-A4E3-1594FC6E48B2}\InprocServer32
		$a_01_10 = {43 6e 73 4d 69 6e 43 67 2e 69 6e 69 } //3 CnsMinCg.ini
		$a_01_11 = {43 6e 73 41 75 74 6f 55 70 64 61 74 65 4d 75 74 65 78 } //4 CnsAutoUpdateMutex
		$a_01_12 = {43 6e 73 4d 69 6e 42 79 70 61 73 73 4e 61 6d 65 4d 75 74 65 78 } //4 CnsMinBypassNameMutex
		$a_01_13 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e 5c 56 61 72 69 61 6e 74 } //3 Software\3721\CnsMin\Variant
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*4+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*3+(#a_01_11  & 1)*4+(#a_01_12  & 1)*4+(#a_01_13  & 1)*3) >=20
 
}
rule Spyware_Win32_CnsMin_13{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 6e 73 2e 64 61 74 } //2 cns.dat
		$a_00_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 63 00 6e 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 } //2 \SystemRoot\cnsinfo.dat
		$a_00_2 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 4e 00 52 00 45 00 44 00 49 00 52 00 45 00 43 00 54 00 } //2 \Registry\Machine\Software\CNREDIRECT
		$a_00_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6e 00 73 00 2e 00 64 00 6c 00 6c 00 } //2 \SystemRoot\System32\cns.dll
		$a_00_4 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6e 00 73 00 2e 00 65 00 78 00 65 00 } //2 \SystemRoot\System32\cns.exe
		$a_00_5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 43 00 6e 00 73 00 4d 00 69 00 6e 00 4b 00 50 00 } //2 \Device\CnsMinKP
		$a_00_6 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 6e 00 73 00 4d 00 69 00 6e 00 4b 00 50 00 } //2 \DosDevices\CnsMinKP
		$a_01_7 = {43 6e 73 6d 69 6e 4b 50 } //2 CnsminKP
		$a_00_8 = {7b 00 44 00 31 00 35 00 37 00 33 00 33 00 30 00 41 00 2d 00 39 00 45 00 46 00 33 00 2d 00 34 00 39 00 46 00 38 00 2d 00 39 00 41 00 36 00 37 00 2d 00 34 00 31 00 34 00 31 00 41 00 43 00 34 00 31 00 41 00 44 00 44 00 34 00 7d 00 } //2 {D157330A-9EF3-49F8-9A67-4141AC41ADD4}
		$a_00_9 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 43 00 6e 00 73 00 4d 00 69 00 6e 00 4b 00 50 00 45 00 76 00 65 00 6e 00 74 00 } //2 \BaseNamedObjects\CnsMinKPEvent
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_01_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2) >=10
 
}
rule Spyware_Win32_CnsMin_14{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 4d 69 6e } //1 Software\3721\CnsMin
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 75 74 6f 2e 73 65 61 72 63 68 2e } //1 http://auto.search.
		$a_01_2 = {63 6e 73 2e 64 6c 6c 3f } //2 cns.dll?
		$a_01_3 = {63 6e 73 2e 33 37 32 31 2e 63 6f 6d } //2 cns.3721.com
		$a_01_4 = {44 65 6c 43 68 69 6e 41 64 64 72 } //1 DelChinAddr
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 21 43 4e 53 5c 52 65 73 65 74 } //1 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\!CNS\Reset
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 21 43 4e 53 5c 4c 69 73 74 } //1 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\!CNS\List
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 49 6e 70 75 74 43 6e 73 } //2 Software\3721\InputCns
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 43 6e 73 55 72 6c } //2 Software\3721\CnsUrl
		$a_00_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 77 6f 72 64 2e 6a 70 2f } //-50 http://www.jword.jp/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_00_9  & 1)*-50) >=11
 
}
rule Spyware_Win32_CnsMin_15{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 73 69 73 74 5c 43 6e 73 4d 69 6e 4b 50 2e } //1 assist\CnsMinKP.
		$a_01_1 = {33 37 32 31 5c 41 73 73 69 73 74 5c 4d 6f 64 75 6c 65 73 } //1 3721\Assist\Modules
		$a_01_2 = {43 61 74 63 68 53 65 78 53 74 79 6c 65 } //1 CatchSexStyle
		$a_01_3 = {5c 6d 73 69 6e 66 6f 73 79 73 2e 64 6c 6c } //1 \msinfosys.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Spyware_Win32_CnsMin_16{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //1 System\CurrentControlSet\Services\CnsMinKP
		$a_01_1 = {63 6e 73 6d 69 6e 2e 64 6c 6c 00 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1
		$a_01_2 = {25 73 5c 79 63 6e 73 2e 64 61 74 } //1 %s\ycns.dat
		$a_01_3 = {5c 33 37 32 31 5c 41 75 74 6f 4c 69 76 65 } //1 \3721\AutoLive
		$a_01_4 = {5c 64 72 69 76 65 72 73 5c 6d 73 64 72 69 76 73 2e 73 79 73 } //1 \drivers\msdrivs.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}