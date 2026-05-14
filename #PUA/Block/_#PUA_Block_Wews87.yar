
rule _#PUA_Block_Wews87{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d } //d.wanyouxi7.com  2
		$a_80_1 = {33 37 6a 7a 63 71 2e 65 78 65 } //37jzcq.exe  1
		$a_80_2 = {6a 7a 63 71 2f 6f 66 66 69 63 69 61 6c 2f 61 70 70 2e 69 6e 69 } //jzcq/official/app.ini  1
		$a_80_3 = {6c 61 6e 64 65 72 2e 70 64 62 } //lander.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Wews87_2{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {3a 2f 2f 64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d 2f 33 37 2f 64 74 73 2f 6f 66 66 69 63 69 61 6c 2f 53 65 74 75 70 5f 33 37 64 74 73 2e 65 78 65 } //1 ://d.wanyouxi7.com/37/dts/official/Setup_37dts.exe
		$a_81_1 = {6c 61 6e 64 65 72 2e 70 64 62 } //1 lander.pdb
		$a_81_2 = {33 37 4c 61 6e 64 65 72 55 70 67 72 61 64 65 2e 65 78 65 } //1 37LanderUpgrade.exe
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_Wews87_3{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 3a 5c 33 37 57 6f 72 6b 5c 70 63 5f 63 6f 64 65 5c 6c 61 6e 64 65 72 5c 74 65 6d 70 6c 61 74 65 5c 6c 69 61 6e 79 75 6e 5c 42 69 6e 5c 6c 61 6e 64 65 72 2e 70 64 62 } //d:\37Work\pc_code\lander\template\lianyun\Bin\lander.pdb  1
		$a_80_1 = {69 63 6f 6e 41 6e 69 6d 61 74 65 2e 65 78 65 } //iconAnimate.exe  1
		$a_80_2 = {4c 61 6e 64 65 72 2e 69 6e 69 } //Lander.ini  1
		$a_80_3 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d } //d.wanyouxi7.com  1
		$a_80_4 = {33 37 77 61 6e 63 6f 6d } //37wancom  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Wews87_4{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d } //d.wanyouxi7.com  2
		$a_80_1 = {33 37 2e 63 6f 6d } //37.com  1
		$a_80_2 = {61 2e 63 6c 69 63 6b 64 61 74 61 2e 33 37 77 61 6e 2e 63 6f 6d } //a.clickdata.37wan.com  1
		$a_80_3 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d 2f 33 37 2f 78 7a 2f 6f 66 66 69 63 69 61 6c 2f 33 37 78 7a 2e 65 78 65 } //d.wanyouxi7.com/37/xz/official/37xz.exe  1
		$a_80_4 = {6c 61 6e 64 65 72 2e 70 64 62 } //lander.pdb  1
		$a_80_5 = {69 63 6f 6e 41 6e 69 6d 61 74 65 2e 70 64 62 } //iconAnimate.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}
rule _#PUA_Block_Wews87_5{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d 2f 33 37 2f 63 71 62 79 2f 6f 66 66 69 63 69 61 6c 2f 61 70 70 2e 69 6e 69 } //d.wanyouxi7.com/37/cqby/official/app.ini  1
		$a_80_1 = {61 2e 63 6c 69 63 6b 64 61 74 61 2e 33 37 77 61 6e 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2f 69 73 74 61 74 2e 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 } //a.clickdata.37wan.com/controller/istat.controller.php  1
		$a_80_2 = {54 78 77 75 2e 65 78 65 } //Txwu.exe  1
		$a_80_3 = {4c 61 6e 64 65 72 2e 69 6e 69 } //Lander.ini  1
		$a_80_4 = {33 5c 42 69 6e 5c 6c 61 6e 64 65 72 2e 70 64 62 } //3\Bin\lander.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Wews87_6{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 78 7a 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //1 \xz\config.ini
		$a_00_1 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 78 7a 5c 63 6f 6e 66 69 67 2e 64 6c 6c } //1 \Application Data\xz\config.dll
		$a_00_2 = {67 61 6d 65 43 6f 72 65 5f 63 65 66 2e 65 78 65 } //1 gameCore_cef.exe
		$a_80_3 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d 2f 33 37 2f 78 7a 2f 6f 66 66 69 63 69 61 6c 2f 33 37 78 7a 2e 65 78 65 } //d.wanyouxi7.com/37/xz/official/37xz.exe  1
		$a_80_4 = {61 2e 63 6c 69 63 6b 64 61 74 61 2e 33 37 77 61 6e 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2f 69 73 74 61 74 2e 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 3f } //a.clickdata.37wan.com/controller/istat.controller.php?  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule _#PUA_Block_Wews87_7{
	meta:
		description = "!#PUA:Block:Wews87,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {64 2e 77 61 6e 79 6f 75 78 69 37 2e 63 6f 6d 2f 33 37 2f 63 71 62 79 2f 6f 66 66 69 63 69 61 6c 2f 61 70 70 2e 69 6e 69 } //d.wanyouxi7.com/37/cqby/official/app.ini  1
		$a_80_1 = {4c 61 6e 64 65 72 2e 69 6e 69 } //Lander.ini  1
		$a_80_2 = {67 61 6d 65 61 70 70 2e 33 37 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2f 63 6c 69 65 6e 74 2e 70 68 70 } //gameapp.37.com/controller/client.php  1
		$a_80_3 = {64 74 73 2e 33 37 2e 63 6f 6d 2f 67 6f 6e 67 6c 75 65 2f } //dts.37.com/gonglue/  1
		$a_80_4 = {45 3a 5c 33 37 57 61 6e 57 6f 72 6b 5c 64 65 6c 70 68 69 63 6f 64 65 5c 76 63 4c 61 6e 64 65 72 5c 63 71 62 79 5f 76 65 72 73 69 6f 6e 33 5c 30 34 } //E:\37WanWork\delphicode\vcLander\cqby_version3\04  1
		$a_80_5 = {5c 42 69 6e 5c 6c 61 6e 64 65 72 2e 70 64 62 } //\Bin\lander.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}