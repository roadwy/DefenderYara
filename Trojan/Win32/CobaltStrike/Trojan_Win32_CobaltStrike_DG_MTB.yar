
rule Trojan_Win32_CobaltStrike_DG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 73 63 6f 64 65 57 6f 72 6b 53 70 61 63 65 5c 73 68 65 6c 6c 63 6f 64 65 5c 77 68 69 74 65 61 6e 64 62 6c 61 63 6b } //1 vscodeWorkSpace\shellcode\whiteandblack
		$a_01_1 = {41 76 61 73 74 53 76 63 2e 65 78 65 } //1 AvastSvc.exe
		$a_01_2 = {6b 70 6d 5f 74 72 61 79 2e 65 78 65 } //1 kpm_tray.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}