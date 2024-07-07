
rule Trojan_Win32_Startpage_WH_dll{
	meta:
		description = "Trojan:Win32/Startpage.WH!dll,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 74 74 6b 64 73 2e 63 6f 6d 2f } //1 .ttkds.com/
		$a_01_1 = {2e 39 39 36 39 2e 6e 65 74 2f } //1 .9969.net/
		$a_01_2 = {7b 37 31 30 36 43 42 46 46 2d 45 45 37 31 2d 34 34 46 35 2d 38 32 39 38 2d 41 34 32 31 33 30 42 46 38 38 43 35 7d } //1 {7106CBFF-EE71-44F5-8298-A42130BF88C5}
		$a_01_3 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 53 75 70 65 72 52 65 70 61 69 72 2e 64 6c 6c 20 2f 73 } //1 regsvr32.exe SuperRepair.dll /s
		$a_01_4 = {73 6f 31 2e 35 6b 35 2e 6e 65 74 2f 69 6e 74 65 72 66 61 63 65 } //1 so1.5k5.net/interface
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}