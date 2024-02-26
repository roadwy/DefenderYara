
rule Trojan_Win32_Banker_ARE_MTB{
	meta:
		description = "Trojan:Win32/Banker.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c0 05 2b d0 8b c2 c3 } //01 00 
		$a_03_1 = {c6 03 e8 8d 56 04 8b c3 e8 90 01 04 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db 90 00 } //01 00 
		$a_01_2 = {63 3a 5c 63 68 69 6e 61 2d 64 72 6d 5c 74 65 6d 70 66 5c } //01 00  c:\china-drm\tempf\
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 53 70 6f 6f 6c 65 72 } //00 00  cmd.exe /c net start Spooler
	condition:
		any of ($a_*)
 
}