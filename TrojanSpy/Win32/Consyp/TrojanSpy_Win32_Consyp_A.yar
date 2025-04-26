
rule TrojanSpy_Win32_Consyp_A{
	meta:
		description = "TrojanSpy:Win32/Consyp.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7c 63 63 53 76 63 48 73 74 2e 65 78 65 7c } //1 |ccSvcHst.exe|
		$a_01_1 = {7c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 7c 73 79 73 74 65 6d 69 6e 66 6f 3b 6e 65 74 73 74 61 74 20 2d 6e 61 3b 6e 65 74 20 75 73 65 3b 6e 65 74 20 75 73 65 72 3b 64 69 72 20 22 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 52 65 63 65 6e 74 22 3b } //1 |WindowsUpdate|systeminfo;netstat -na;net use;net user;dir "%USERPROFILE%\Recent";
		$a_01_2 = {2f 69 6e 64 65 78 2e 70 68 70 3b 68 74 74 70 3a 2f 2f } //1 /index.php;http://
		$a_01_3 = {5c 53 74 61 72 74 75 70 5c 77 75 61 75 63 6c 74 2e 65 78 65 22 20 2f 79 20 26 20 72 65 67 20 61 64 64 } //1 \Startup\wuauclt.exe" /y & reg add
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}