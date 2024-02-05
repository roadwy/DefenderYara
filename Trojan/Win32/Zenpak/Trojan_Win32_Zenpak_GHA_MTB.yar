
rule Trojan_Win32_Zenpak_GHA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 33 d2 6a 20 59 f7 f1 8b 45 ec 0f b6 04 10 8b 4d f4 03 4d f0 0f b6 09 2b c8 8b 45 f4 03 45 f0 88 08 eb } //01 00 
		$a_80_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4f 70 65 6e 67 6c 5f 33 2e 30 2e 31 2e 6c 6f 67 } //C:\Windows\Opengl_3.0.1.log  00 00 
	condition:
		any of ($a_*)
 
}