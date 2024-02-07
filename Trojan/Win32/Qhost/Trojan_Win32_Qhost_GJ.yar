
rule Trojan_Win32_Qhost_GJ{
	meta:
		description = "Trojan:Win32/Qhost.GJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {f3 a4 75 cc bb 0f 00 00 00 8d b4 24 0f 08 00 00 80 3e 40 74 4c } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 65 73 74 73 22 2c 4f 76 65 72 77 72 69 74 65 45 78 69 73 74 69 6e 67 } //01 00  system32\drivers\etc\hests",OverwriteExisting
		$a_01_2 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 22 22 20 2f 59 20 26 26 20 61 74 74 72 69 62 20 2b 48 } //00 00  system32\drivers\etc\hosts"" /Y && attrib +H
	condition:
		any of ($a_*)
 
}