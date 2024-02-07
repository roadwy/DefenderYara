
rule Trojan_O97M_Obfuse_CC{
	meta:
		description = "Trojan:O97M/Obfuse.CC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 53 79 73 22 20 26 } //01 00  = Environ("Sys" &
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 } //01 00  = CreateObject("scripting.filesystemobject")
		$a_01_2 = {28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4d 61 69 6c 53 79 73 74 65 6d 29 20 4c 69 6b 65 } //00 00  (Application.MailSystem) Like
	condition:
		any of ($a_*)
 
}