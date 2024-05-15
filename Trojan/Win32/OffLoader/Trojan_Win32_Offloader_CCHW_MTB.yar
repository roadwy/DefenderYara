
rule Trojan_Win32_Offloader_CCHW_MTB{
	meta:
		description = "Trojan:Win32/Offloader.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 63 69 65 6e 63 65 65 64 75 63 61 74 69 6f 6e 2e 6f 6e 6c 69 6e 65 2f 69 72 2f 73 72 65 62 2e 70 68 70 3f } //01 00  scienceeducation.online/ir/sreb.php?
		$a_81_1 = {2f 73 69 6c 65 6e 74 } //01 00  /silent
		$a_81_2 = {72 75 6e 2e 62 61 74 } //00 00  run.bat
	condition:
		any of ($a_*)
 
}