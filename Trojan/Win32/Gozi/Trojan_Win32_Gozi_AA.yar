
rule Trojan_Win32_Gozi_AA{
	meta:
		description = "Trojan:Win32/Gozi.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 66 72 6f 6d 45 78 65 5c 45 45 45 45 45 45 5c 67 6f 6f 67 6c 65 5f 63 68 72 6f 6d 65 2e 65 78 65 2e 3d 2c 2e 70 64 62 } //1 F:\fromExe\EEEEEE\google_chrome.exe.=,.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}