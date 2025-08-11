
rule Trojan_Win32_EvasionViaPathExclusion_AD{
	meta:
		description = "Trojan:Win32/EvasionViaPathExclusion.AD,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 61 00 69 00 71 00 } //3 powershell.exe add-mppreference -exclusionpath %temp%\aiq
	condition:
		((#a_00_0  & 1)*3) >=3
 
}