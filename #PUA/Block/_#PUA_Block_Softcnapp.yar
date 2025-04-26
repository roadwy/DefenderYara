
rule _#PUA_Block_Softcnapp{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {35 31 78 75 61 6e 62 69 6e } //51xuanbin  1
		$a_80_1 = {43 49 63 6f 50 72 6f 2e 65 78 65 } //CIcoPro.exe  1
		$a_80_2 = {74 6a 2e 70 65 69 6c 61 6e 63 61 6f 2e 63 6e } //tj.peilancao.cn  1
		$a_80_3 = {43 6c 69 50 72 61 5f 49 6e 5f } //CliPra_In_  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Softcnapp_2{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 6f 67 6f 75 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //sogouexplorer.exe  1
		$a_80_1 = {43 6c 6f 76 65 72 2e 65 78 65 } //Clover.exe  1
		$a_80_2 = {65 6a 69 65 2e 6d 65 } //ejie.me  1
		$a_80_3 = {75 70 64 6d 70 2e 73 68 75 73 77 2e 63 6f 6d } //updmp.shusw.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Softcnapp_3{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 68 69 6e 61 76 69 70 73 6f 66 74 2e 63 6f 6d } //chinavipsoft.com  1
		$a_80_1 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_2 = {57 61 6e 4e 65 6e 67 5a 69 70 2e 69 6e 69 } //WanNengZip.ini  1
		$a_80_3 = {55 6e 69 6e 73 74 46 69 6e 69 73 68 42 67 53 6b 69 6e } //UninstFinishBgSkin  -10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-10) >=3
 
}
rule _#PUA_Block_Softcnapp_4{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {65 6c 65 70 68 61 6e 74 70 64 66 [0-0f] 2e 79 65 62 61 6e 6b 65 6a 69 2e 63 6e } //1
		$a_80_1 = {45 68 50 44 46 } //EhPDF  1
		$a_80_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 45 6c 65 70 68 61 6e 74 } //Program Files\Elephant  1
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -5
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-5) >=3
 
}
rule _#PUA_Block_Softcnapp_5{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {74 6a 2e 70 65 69 6c 61 6e 63 61 6f 2e 63 6e } //tj.peilancao.cn  1
		$a_80_1 = {2f 6c 6f 67 2f 73 65 6e 64 6d 73 67 2e 70 68 70 } ///log/sendmsg.php  1
		$a_80_2 = {6c 6f 72 65 2e 65 78 65 } //lore.exe  1
		$a_80_3 = {43 49 63 6f 50 72 6f 2e 65 78 65 } //CIcoPro.exe  1
		$a_80_4 = {35 31 78 75 61 6e 62 69 6e 2e 65 78 65 } //51xuanbin.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_6{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 61 63 63 6f 6f 6e 57 69 66 69 } //RaccoonWifi  1
		$a_80_1 = {49 6e 73 74 61 6c 6c 50 61 74 68 } //InstallPath  1
		$a_80_2 = {75 73 65 72 63 6f 6e 66 69 67 2e 69 6e 69 } //userconfig.ini  1
		$a_80_3 = {52 61 63 63 6f 6f 6e 57 69 66 69 2e 69 6e 69 } //RaccoonWifi.ini  1
		$a_80_4 = {52 61 63 63 6f 6f 6e 57 69 66 69 2e 63 66 67 } //RaccoonWifi.cfg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_7{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 44 43 6f 6e 66 69 67 2e 65 78 65 } //PDConfig.exe  1
		$a_80_1 = {77 6e 69 65 2e 65 78 65 } //wnie.exe  1
		$a_80_2 = {73 6f 67 6f 75 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //sogouexplorer.exe  1
		$a_80_3 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_4 = {50 75 64 64 69 6e 67 44 65 73 6b 74 6f 70 2e 69 6e 69 } //PuddingDesktop.ini  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_8{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 63 2e 77 6e 35 31 2e 63 6f 6d 2f 77 6b 62 67 6c 2e 70 68 70 } //wc.wn51.com/wkbgl.php  2
		$a_80_1 = {4c 6f 63 61 6c 4c 6f 77 5c 53 68 6b 62 5c 43 6f 6e 66 69 67 2e 69 6e 69 } //LocalLow\Shkb\Config.ini  1
		$a_80_2 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_3 = {57 61 6e 4e 65 6e 67 49 6e 73 74 61 6c 6c 2e 70 64 62 } //WanNengInstall.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_9{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 61 63 6b 73 74 61 67 65 77 77 77 2e 77 6e 77 62 2e 63 6f 6d } //backstagewww.wnwb.com  2
		$a_80_1 = {57 6e 55 73 65 72 50 61 67 65 2e 65 78 65 } //WnUserPage.exe  1
		$a_80_2 = {53 6f 66 74 53 6b 69 6e } //SoftSkin  1
		$a_80_3 = {57 61 6e 4e 65 6e 67 57 42 49 4d 45 2e 75 73 65 72 73 } //WanNengWBIME.users  1
		$a_80_4 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_10{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 6e 77 62 2e 65 78 65 } //wnwb.exe  2
		$a_80_1 = {74 6a 74 76 33 2e 77 6e 35 31 2e 63 6f 6d } //tjtv3.wn51.com  1
		$a_80_2 = {77 77 77 2e 77 6e 77 62 2e 63 6f 6d 2f 70 6f 6c 69 63 79 2e 68 74 6d 6c } //www.wnwb.com/policy.html  1
		$a_80_3 = {57 61 6e 4e 65 6e 67 57 42 49 6e 66 6f 2e 69 6e 69 } //WanNengWBInfo.ini  1
		$a_80_4 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_11{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 58 73 50 69 63 74 75 72 65 5c 58 73 50 69 63 4d 65 61 6e 73 2e 65 78 65 } //C:\Program Files\XsPicture\XsPicMeans.exe  1
		$a_80_1 = {7a 79 63 75 6c 74 75 72 61 2e 63 6f 6d } //zycultura.com  1
		$a_80_2 = {58 73 50 69 63 49 6e 66 6f 2e 69 6e 69 } //XsPicInfo.ini  1
		$a_80_3 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-5) >=4
 
}
rule _#PUA_Block_Softcnapp_12{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {58 69 6e 53 75 5a 69 70 2e 69 6e 69 } //XinSuZip.ini  2
		$a_80_1 = {74 6a 69 2e 7a 68 69 6c 69 6e 67 73 68 69 64 61 69 2e 63 6f 6d } //tji.zhilingshidai.com  2
		$a_80_2 = {64 6f 77 6e 2e 7a 68 69 6c 69 6e 67 73 68 69 64 61 69 2e 63 6f 6d } //down.zhilingshidai.com  1
		$a_80_3 = {55 73 65 49 6e 66 6f 2e 69 6e 69 } //UseInfo.ini  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=5
 
}
rule _#PUA_Block_Softcnapp_13{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {4d 47 57 61 6c 6c 70 61 70 65 72 } //MGWallpaper  1
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 47 57 61 6c 6c 70 61 70 65 72 5c } //C:\Program Files\MGWallpaper\  1
		$a_00_2 = {73 6f 66 74 74 6a 2e 70 61 6e 73 68 69 78 6b 2e 63 6f 6d } //1 softtj.panshixk.com
		$a_80_3 = {4d 67 57 61 6c 6c 2e 65 78 65 } //MgWall.exe  1
		$a_80_4 = {50 65 72 73 69 73 74 42 61 72 5f 4f 6e 43 6f 6e 74 69 6e 75 65 55 6e 69 6e 73 74 } //PersistBar_OnContinueUninst  -5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-5) >=4
 
}
rule _#PUA_Block_Softcnapp_14{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 64 63 64 6e 2e 6a 69 61 2d 73 69 2e 63 6e 2f 63 66 67 2e 64 61 74 } //downdcdn.jia-si.cn/cfg.dat  1
		$a_80_1 = {77 63 2e 6a 69 61 2d 73 69 2e 63 6e 2f 77 6b 62 67 6c 2e 70 68 70 } //wc.jia-si.cn/wkbgl.php  1
		$a_80_2 = {5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 2e 65 78 65 } //ZhuDongFangYu.exe  1
		$a_80_3 = {5c 4c 6f 63 61 6c 4c 6f 77 5c 53 68 6b 62 5c 43 6f 6e 66 69 67 2e 69 6e 69 } //\LocalLow\Shkb\Config.ini  1
		$a_80_4 = {77 6e 73 6f 66 74 2e 69 6e 69 } //wnsoft.ini  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_15{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 2e 78 73 66 61 79 61 2e 63 6f 6d 2f 6d 69 6e 69 2f 70 72 69 63 65 } //soft.xsfaya.com/mini/price  1
		$a_80_1 = {43 3a 5c 4e 6f 53 68 6f 77 48 74 74 70 43 6f 6e 74 65 2e 6e 74 6c } //C:\NoShowHttpConte.ntl  1
		$a_80_2 = {4d 69 6e 69 50 61 67 65 2e 65 78 65 } //MiniPage.exe  1
		$a_80_3 = {6f 74 74 2e 78 73 66 61 79 61 2e 63 6f 6d } //ott.xsfaya.com  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=4
 
}
rule _#PUA_Block_Softcnapp_16{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {58 73 50 69 63 49 6e 66 6f 2e 69 6e 69 } //XsPicInfo.ini  2
		$a_80_1 = {7a 79 63 75 6c 74 75 72 61 2e 63 6f 6d } //zycultura.com  2
		$a_80_2 = {58 73 50 69 63 56 69 65 77 } //XsPicView  1
		$a_02_3 = {58 00 73 00 50 00 69 00 63 00 [0-0f] 2e 00 65 00 78 00 65 00 } //1
		$a_02_4 = {58 73 50 69 63 [0-0f] 2e 65 78 65 } //1
		$a_80_5 = {58 73 50 69 63 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //XsPicUninstall.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}
rule _#PUA_Block_Softcnapp_17{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 6d 6d 74 6b 6d 2e 7a 73 69 6e 63 65 72 2e 63 6f 6d 2f 70 64 66 2f 6a 69 6b 65 2f 33 32 66 63 32 62 34 32 64 35 35 36 61 33 38 37 64 31 63 39 34 34 62 64 30 64 35 33 30 61 32 62 2e 64 65 64 } //http://mmtkm.zsincer.com/pdf/jike/32fc2b42d556a387d1c944bd0d530a2b.ded  1
		$a_80_1 = {4a 6b 52 74 72 6f 6e 2e 65 78 65 } //JkRtron.exe  1
		$a_80_2 = {48 6f 6c 6c 6f 6e 2e 69 6e 69 } //Hollon.ini  1
		$a_80_3 = {6d 69 6e 6b 65 72 6e 65 6c 5c 63 72 74 73 5c 75 63 72 74 5c 69 6e 63 5c 63 6f 72 65 63 72 74 5f 69 6e 74 65 72 6e 61 6c 5f 73 74 72 74 6f 78 2e 68 } //minkernel\crts\ucrt\inc\corecrt_internal_strtox.h  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Softcnapp_18{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 57 53 6b 69 6e 49 6e 73 74 2e 65 78 65 } //SWSkinInst.exe  1
		$a_80_1 = {43 6f 6e 66 69 67 5c 55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //Config\UseVestige.ini  1
		$a_80_2 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_3 = {53 6d 61 72 74 43 6c 6f 75 64 57 42 49 6e 66 6f 2e 69 6e 69 } //SmartCloudWBInfo.ini  1
		$a_80_4 = {45 3a 5c 67 69 74 5c 73 68 75 72 75 66 61 5c 73 72 63 5c 49 6d 65 57 42 5c 42 75 6e 64 6c 65 73 5c 53 6d 61 72 74 43 6c 6f 75 64 5c 42 69 6e 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 53 6b 69 6e 52 65 67 33 32 2e 70 64 62 } //E:\git\shurufa\src\ImeWB\Bundles\SmartCloud\Bin\pdbmap\WanNeng\SkinReg32.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_19{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {6c 61 6f 68 75 61 6e 67 6c 69 33 36 35 2e 63 6f 6d } //laohuangli365.com  2
		$a_80_1 = {6e 73 6b 32 38 39 30 2e 74 6d 70 } //nsk2890.tmp  1
		$a_80_2 = {6e 73 75 2e 74 6d 70 } //nsu.tmp  1
		$a_80_3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //AdjustTokenPrivileges  1
		$a_80_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //SeShutdownPrivilege  1
		$a_80_5 = {44 65 73 74 72 6f 79 57 69 6e 64 6f 77 } //DestroyWindow  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=6
 
}
rule _#PUA_Block_Softcnapp_20{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {6a 63 78 79 74 2e 63 61 6e 67 79 61 6b 65 6a 69 2e 63 6e 2f 69 6d 61 67 65 2f 69 6e 6b 2f 64 64 35 64 34 62 38 31 38 37 33 63 63 38 62 65 38 31 32 32 30 65 62 30 33 32 30 35 63 39 63 33 2e 62 62 66 } //jcxyt.cangyakeji.cn/image/ink/dd5d4b81873cc8be81220eb03205c9c3.bbf  1
		$a_80_1 = {49 6e 6b 49 6d 67 45 73 65 2e 65 78 65 } //InkImgEse.exe  1
		$a_80_2 = {49 6e 6b 49 6d 67 45 73 64 2e 64 6c 6c } //InkImgEsd.dll  1
		$a_80_3 = {6d 69 6e 6b 65 72 6e 65 6c 5c 63 72 74 73 5c 75 63 72 74 5c 69 6e 63 5c 63 6f 72 65 63 72 74 5f 69 6e 74 65 72 6e 61 6c 5f 73 74 72 74 6f 78 2e 68 } //minkernel\crts\ucrt\inc\corecrt_internal_strtox.h  1
		$a_80_4 = {49 69 76 52 69 70 } //IivRip  1
		$a_80_5 = {49 69 76 52 69 70 2e 63 66 67 } //IivRip.cfg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Softcnapp_21{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 43 4d 75 74 75 61 6c 2e 65 78 65 } //SCMutual.exe  1
		$a_80_1 = {53 43 43 6f 6e 66 69 67 2e 65 78 65 } //SCConfig.exe  1
		$a_80_2 = {73 63 69 65 2e 65 78 65 } //scie.exe  1
		$a_80_3 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_80_4 = {5c 54 72 75 6e 6b 50 59 5c 42 69 6e 5c 70 64 62 6d 61 70 5c 53 6d 61 72 74 43 6c 6f 75 64 5c 4d 6f 6e 69 74 65 72 33 32 2e 70 64 62 } //\TrunkPY\Bin\pdbmap\SmartCloud\Moniter32.pdb  1
		$a_80_5 = {68 68 63 74 72 6c 2e 6f 63 78 } //hhctrl.ocx  1
		$a_80_6 = {66 3a 5c 73 70 5c 76 63 74 6f 6f 6c 73 5c 76 63 37 6c 69 62 73 5c 73 68 69 70 5c 61 74 6c 6d 66 63 5c 73 72 63 5c 6d 66 63 5c 61 70 70 63 6f 72 65 2e 63 70 70 } //f:\sp\vctools\vc7libs\ship\atlmfc\src\mfc\appcore.cpp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_Softcnapp_22{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 } //CreatePopupMenu  1
		$a_80_1 = {43 4d 59 57 4e 44 5f 4d 49 4e 49 50 41 47 45 } //CMYWND_MINIPAGE  1
		$a_80_2 = {43 4d 59 57 4e 44 5f 4d 49 4e 49 50 41 47 45 3d 50 6f 70 75 70 } //CMYWND_MINIPAGE=Popup  1
		$a_80_3 = {41 50 50 5f 4d 49 4e 49 50 41 47 45 5f 45 58 45 3d 54 72 61 76 69 73 2e 65 78 65 } //APP_MINIPAGE_EXE=Travis.exe  1
		$a_80_4 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //MiniDumpWriteDump  1
		$a_80_5 = {6f 70 74 2e 76 6b 75 70 64 66 2e 63 6f 6d } //opt.vkupdf.com  1
		$a_80_6 = {42 65 73 74 5a 69 70 2e 65 78 65 } //BestZip.exe  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=7
 
}
rule _#PUA_Block_Softcnapp_23{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_80_0 = {50 44 46 52 65 61 64 65 72 } //PDFReader  1
		$a_80_1 = {50 44 46 56 69 65 77 } //PDFView  1
		$a_80_2 = {5a 68 6f 6e 67 48 75 61 50 64 66 } //ZhongHuaPdf  1
		$a_80_3 = {4a 4b 43 6f 76 55 70 64 } //JKCovUpd  1
		$a_80_4 = {63 68 69 6e 61 76 69 70 73 6f 66 74 2e 63 6f 6d } //chinavipsoft.com  1
		$a_80_5 = {7a 73 69 6e 63 65 72 2e 63 6f 6d } //zsincer.com  1
		$a_80_6 = {53 6f 61 6f 64 77 61 69 66 65 2e 69 6e 69 } //Soaodwaife.ini  1
		$a_80_7 = {4a 4b 43 6f 76 79 62 61 77 62 79 2e 69 6e 69 } //JKCovybawby.ini  1
		$a_80_8 = {4a 69 6b 65 50 44 46 43 6f 6e 76 65 72 74 65 72 2e 69 6e 69 } //JikePDFConverter.ini  1
		$a_80_9 = {5a 48 50 44 46 49 6e 66 6f 2e 69 6e 69 } //ZHPDFInfo.ini  1
		$a_80_10 = {55 6e 69 6e 73 74 46 69 6e 69 73 68 42 67 53 6b 69 6e } //UninstFinishBgSkin  -5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*-5) >=3
 
}
rule _#PUA_Block_Softcnapp_24{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0c 00 00 "
		
	strings :
		$a_80_0 = {79 6d 6a 71 6e 2e 62 69 6a 69 61 74 75 2e 63 6f 6d } //ymjqn.bijiatu.com  1
		$a_80_1 = {5a 68 6f 6e 67 58 69 61 6e 67 57 69 46 69 2e 69 6e 69 } //ZhongXiangWiFi.ini  1
		$a_80_2 = {4b 6f 61 6c 61 57 61 6c 6c 2e 69 6e 69 } //KoalaWall.ini  1
		$a_80_3 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_00_4 = {7a 6d 69 77 6e 2e 62 69 6a 69 61 74 75 2e 63 6f 6d } //1 zmiwn.bijiatu.com
		$a_80_5 = {4e 69 75 58 69 61 6f 51 75 61 6e 2e 69 6e 69 } //NiuXiaoQuan.ini  1
		$a_80_6 = {4e 58 51 53 68 6f 70 70 69 6e 67 2e 65 78 65 } //NXQShopping.exe  1
		$a_80_7 = {46 6f 74 68 6f 6c 70 69 64 64 2e 69 6e 69 } //Fotholpidd.ini  1
		$a_80_8 = {46 6c 69 72 74 63 6b 79 6f 75 73 } //Flirtckyous  1
		$a_80_9 = {4d 75 6f 74 65 72 69 6e 65 2e 69 6e 69 } //Muoterine.ini  1
		$a_80_10 = {59 61 72 6e 72 6f 75 6e 64 } //Yarnround  1
		$a_80_11 = {55 6e 69 6e 73 74 46 69 6e 69 73 68 42 67 53 6b 69 6e } //UninstFinishBgSkin  -5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*-5) >=3
 
}
rule _#PUA_Block_Softcnapp_25{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {74 6a 73 6f 66 74 2e } //tjsoft.  1
		$a_80_1 = {2f 66 64 6f 74 2e 70 68 70 3f 64 61 74 61 3d } ///fdot.php?data=  1
		$a_00_2 = {6a 00 69 00 61 00 2d 00 73 00 69 00 2e 00 63 00 6e 00 2f 00 61 00 70 00 69 00 2e 00 70 00 68 00 70 00 } //1 jia-si.cn/api.php
		$a_00_3 = {31 00 30 00 31 00 2e 00 33 00 37 00 2e 00 31 00 38 00 38 00 2e 00 34 00 32 00 2f 00 } //1 101.37.188.42/
		$a_00_4 = {64 00 6f 00 77 00 6e 00 64 00 63 00 64 00 6e 00 2e 00 6a 00 69 00 61 00 2d 00 73 00 69 00 2e 00 63 00 6e 00 2f 00 78 00 69 00 61 00 7a 00 61 00 69 00 71 00 69 00 2f 00 78 00 69 00 61 00 7a 00 61 00 69 00 71 00 69 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 downdcdn.jia-si.cn/xiazaiqi/xiazaiqi.html
		$a_00_5 = {6b 00 78 00 65 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 7c 00 6b 00 78 00 65 00 73 00 63 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //1 kxetray.exe|kxescore.exe
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Softcnapp_26{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 69 78 65 64 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 } //\Mixed\pdbmap\WanNeng\Install.pdb  1
		$a_02_1 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 [0-0f] 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 42 00 75 00 6e 00 64 00 6c 00 65 00 42 00 69 00 6e 00 64 00 5c 00 } //1
		$a_02_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c [0-0f] 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 42 75 6e 64 6c 65 42 69 6e 64 5c } //1
		$a_80_3 = {55 73 65 56 65 73 74 69 67 65 2e 69 6e 69 } //UseVestige.ini  1
		$a_02_4 = {64 00 6f 00 77 00 6e 00 2e 00 [0-1f] 2e 00 63 00 6f 00 6d 00 } //1
		$a_02_5 = {64 6f 77 6e 2e [0-1f] 2e 63 6f 6d } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=4
 
}
rule _#PUA_Block_Softcnapp_27{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 69 78 65 64 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 } //\Mixed\pdbmap\WanNeng\Install.pdb  2
		$a_02_1 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 [0-0f] 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 42 00 75 00 6e 00 64 00 6c 00 65 00 42 00 69 00 6e 00 64 00 5c 00 } //1
		$a_02_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c [0-0f] 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 42 75 6e 64 6c 65 42 69 6e 64 5c } //1
		$a_02_3 = {64 00 6f 00 77 00 6e 00 2e 00 [0-1f] 2e 00 63 00 6f 00 6d 00 } //2
		$a_02_4 = {64 6f 77 6e 2e [0-1f] 2e 63 6f 6d } //2
		$a_80_5 = {20 51 51 50 43 54 72 61 79 2e 65 78 65 } // QQPCTray.exe  1
		$a_80_6 = {77 6e 73 6f 66 74 2e 69 6e 69 } //wnsoft.ini  1
	condition:
		((#a_80_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}
rule _#PUA_Block_Softcnapp_28{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 10 84 f5 74 ff ff ff 8b 8d 38 ff ff ff 83 ec 10 0f 11 04 24 e8 84 bb f7 ff 83 c6 02 3b f7 7c df } //1
		$a_01_1 = {0f 10 84 f5 74 ff ff ff 8b 8d 38 ff ff ff 83 ec 10 0f 11 04 24 e8 b6 bb f7 ff 83 c6 02 3b f7 7c df } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#PUA_Block_Softcnapp_29{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 73 74 2e 63 6f 6d 2f 77 75 6d 69 6e 67 2f 70 6e 67 2f 6d 6f 6e 69 64 73 2e 70 6e 67 } //1 est.com/wuming/png/monids.png
		$a_01_1 = {64 77 6f 6e 6c 6f 61 64 2e 73 69 6e 6f 73 74 65 65 6c 69 6e 76 65 73 74 2e 63 6f 6d } //1 dwonload.sinosteelinvest.com
		$a_01_2 = {44 3a 5c 58 69 61 5a 61 69 51 69 5c 50 72 6f 6a 65 63 74 43 6f 70 79 5c 4d 69 78 65 64 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 } //1 D:\XiaZaiQi\ProjectCopy\Mixed\pdbmap\WanNeng\Install.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_Softcnapp_30{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 54 72 75 6e 6b 50 59 5c 42 69 6e 5c 70 64 62 6d 61 70 5c 53 6d 61 72 74 43 6c 6f 75 64 5c 4d 75 74 75 61 6c 33 32 2e 70 64 62 } //1 \TrunkPY\Bin\pdbmap\SmartCloud\Mutual32.pdb
		$a_01_1 = {53 43 4d 75 74 75 61 6c 2e 65 78 65 } //1 SCMutual.exe
		$a_01_2 = {2e 00 7a 00 6e 00 73 00 68 00 75 00 72 00 75 00 2e 00 63 00 6f 00 6d 00 } //1 .znshuru.com
		$a_01_3 = {74 6a 74 76 33 2e 7a 6e 79 73 68 75 72 75 66 61 2e 63 6f 6d 2f } //1 tjtv3.znyshurufa.com/
		$a_01_4 = {73 00 70 00 61 00 72 00 6b 00 2e 00 65 00 78 00 65 00 74 00 68 00 65 00 77 00 6f 00 72 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //1 spark.exetheworld.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#PUA_Block_Softcnapp_31{
	meta:
		description = "!#PUA:Block:Softcnapp,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 6a 69 2e 6c 65 69 73 75 72 65 6c 79 70 61 6e 64 61 2e 63 6f 6d } //1 tji.leisurelypanda.com
		$a_01_1 = {5c 00 42 00 75 00 6e 00 64 00 6c 00 65 00 73 00 5c 00 4c 00 69 00 74 00 74 00 6c 00 65 00 5c 00 53 00 6f 00 66 00 74 00 53 00 6b 00 69 00 6e 00 } //1 \Bundles\Little\SoftSkin
		$a_01_2 = {4c 00 69 00 74 00 74 00 6c 00 65 00 50 00 69 00 63 00 } //1 LittlePic
		$a_01_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4c 00 69 00 74 00 74 00 6c 00 65 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 } //1 C:\Program Files\LittlePicture
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}