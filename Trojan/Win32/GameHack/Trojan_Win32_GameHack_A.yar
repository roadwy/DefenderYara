
rule Trojan_Win32_GameHack_A{
	meta:
		description = "Trojan:Win32/GameHack.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 68 79 67 61 6d 65 38 38 38 38 2e 63 6e } //1 .hygame8888.cn
		$a_01_1 = {2f 63 38 63 5f 69 6e 69 2f 73 74 61 72 74 75 70 2e } //1 /c8c_ini/startup.
		$a_01_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 33 2e 69 6e 69 } //1 \drivers\etc\service3.ini
		$a_01_3 = {5c 73 74 61 72 74 75 70 31 2e 65 78 65 } //1 \startup1.exe
		$a_01_4 = {2f 45 78 65 49 6e 69 2f 63 38 63 43 6f 6e 66 69 67 32 5f 72 75 6e 2e 74 78 74 } //1 /ExeIni/c8cConfig2_run.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}