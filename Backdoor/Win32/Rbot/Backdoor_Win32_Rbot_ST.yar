
rule Backdoor_Win32_Rbot_ST{
	meta:
		description = "Backdoor:Win32/Rbot.ST,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 68 00 6b 00 69 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 \hkicmd.exe
		$a_00_1 = {43 00 3a 00 5c 00 42 00 75 00 69 00 6c 00 64 00 73 00 5c 00 54 00 50 00 5c 00 69 00 6e 00 64 00 79 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 5c 00 6c 00 69 00 62 00 5c 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 73 00 5c 00 49 00 64 00 48 00 54 00 54 00 50 00 2e 00 70 00 61 00 73 00 } //1 C:\Builds\TP\indysockets\lib\Protocols\IdHTTP.pas
		$a_02_2 = {8b f3 81 e6 f0 00 00 00 83 fe 40 77 90 01 01 6a 00 68 80 00 00 00 6a 02 6a 00 c1 ee 04 8b 04 b5 90 01 03 00 50 68 00 00 00 c0 8b c7 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}