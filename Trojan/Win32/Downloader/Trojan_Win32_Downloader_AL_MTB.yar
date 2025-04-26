
rule Trojan_Win32_Downloader_AL_MTB{
	meta:
		description = "Trojan:Win32/Downloader.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 10 80 f2 ?? 80 c2 ?? 88 10 83 c0 01 83 e9 01 75 e6 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //2 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}