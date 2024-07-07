
rule Trojan_Win32_DarkGate_EB_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 37 38 2e 32 33 36 2e 32 34 37 2e 31 30 32 3a 39 39 39 39 } //1 178.236.247.102:9999
		$a_01_1 = {6c 73 61 73 73 2e 65 78 65 7c 6b 61 76 2e 65 78 65 7c 61 76 70 63 63 2e 65 78 65 7c 5f 61 76 70 6d 2e 65 78 65 7c 61 76 70 33 32 2e 65 78 65 7c 61 76 70 2e 65 78 65 7c 61 6e 74 69 76 69 72 75 73 2e 65 78 65 7c } //1 lsass.exe|kav.exe|avpcc.exe|_avpm.exe|avp32.exe|avp.exe|antivirus.exe|
		$a_01_2 = {2d 2d 6d 75 74 65 2d 61 75 64 69 6f 20 2d 2d 64 69 73 61 62 6c 65 2d 61 75 64 69 6f 20 2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 6e 65 77 2d 77 69 6e 64 6f 77 20 2d 2d 64 69 73 61 62 6c 65 2d 33 64 2d 61 70 69 73 } //1 --mute-audio --disable-audio --no-sandbox --new-window --disable-3d-apis
		$a_01_3 = {2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 20 2d 2d 64 69 73 61 62 6c 65 2d 64 33 64 31 31 20 2d 2d 77 69 6e 64 6f 77 2d 73 69 7a 65 3d } //1 --disable-gpu --disable-d3d11 --window-size=
		$a_01_4 = {52 53 41 63 74 69 6f 6e 53 65 6e 64 48 51 53 63 72 65 65 6e 73 68 6f 74 } //1 RSActionSendHQScreenshot
		$a_01_5 = {64 61 72 6b 67 61 74 65 2e 63 6f 6d } //1 darkgate.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}