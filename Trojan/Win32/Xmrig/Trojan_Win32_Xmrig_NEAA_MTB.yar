
rule Trojan_Win32_Xmrig_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 4c 24 24 8b 74 24 34 8d 54 24 24 0f 43 4c 24 24 8b 7b 38 03 f1 83 7c 24 38 10 8d 4c 24 1c 51 0f 43 54 24 28 8d 4c 24 28 8b 07 51 8d 4c 24 2b 51 8d 4c 24 24 51 56 52 8d 4b 40 51 8b cf ff 50 18 83 e8 00 } //10
		$a_01_1 = {75 75 61 55 48 42 61 48 42 31 39 61 5a 31 } //2 uuaUHBaHB19aZ1
		$a_01_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //2 C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}