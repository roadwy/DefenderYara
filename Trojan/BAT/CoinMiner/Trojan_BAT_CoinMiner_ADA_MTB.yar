
rule Trojan_BAT_CoinMiner_ADA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //[InternetShortcut]  3
		$a_80_1 = {2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 20 26 26 20 74 61 73 6b 6d 67 72 20 26 26 } ///C ping 127.0.0.1 -n 2 && taskmgr &&  3
		$a_80_2 = {63 66 67 2e 74 78 74 } //cfg.txt  3
		$a_80_3 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 53 79 73 66 69 6c 65 73 5c } //\AppData\Roaming\Sysfiles\  3
		$a_80_4 = {2d 70 20 78 20 2d 6b 20 2d 76 3d 30 20 2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 3d 31 20 2d 74 } //-p x -k -v=0 --donate-level=1 -t  3
		$a_80_5 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 } //ProcessHacker  3
		$a_80_6 = {64 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 63 65 63 75 74 65 } //downloadAndExcecute  3
		$a_80_7 = {77 69 6e 33 32 5f 6c 6f 67 69 63 61 6c 64 69 73 6b 2e 64 65 76 69 63 65 69 64 3d } //win32_logicaldisk.deviceid=  3
		$a_80_8 = {3f 68 77 69 64 3d } //?hwid=  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}