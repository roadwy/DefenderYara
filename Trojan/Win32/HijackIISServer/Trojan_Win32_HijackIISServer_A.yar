
rule Trojan_Win32_HijackIISServer_A{
	meta:
		description = "Trojan:Win32/HijackIISServer.A,SIGNATURE_TYPE_CMDHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //0a 00  powershell
		$a_00_1 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //05 00  net.webclient
		$a_00_2 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //05 00  .downloadstring(
		$a_00_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 } //ce ff  .downloadfile(
		$a_00_4 = {63 00 68 00 6f 00 63 00 6f 00 6c 00 61 00 74 00 65 00 79 00 } //ce ff  chocolatey
		$a_00_5 = {65 00 64 00 67 00 65 00 73 00 65 00 72 00 76 00 65 00 72 00 70 00 75 00 62 00 6c 00 69 00 73 00 68 00 2e 00 6f 00 72 00 74 00 68 00 6f 00 69 00 69 00 2e 00 63 00 6f 00 6d 00 } //ce ff  edgeserverpublish.orthoii.com
		$a_00_6 = {77 00 69 00 6e 00 72 00 6d 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //00 00  winrmusername
	condition:
		any of ($a_*)
 
}