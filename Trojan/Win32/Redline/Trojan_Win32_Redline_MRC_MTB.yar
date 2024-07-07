
rule Trojan_Win32_Redline_MRC_MTB{
	meta:
		description = "Trojan:Win32/Redline.MRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 8d 90 01 04 0f b6 11 33 d0 8b 45 08 03 85 90 01 04 88 10 8d 8d 90 00 } //1
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 52 65 67 41 73 6d 2e 65 78 65 } //1 C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}