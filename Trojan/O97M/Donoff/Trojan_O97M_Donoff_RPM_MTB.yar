
rule Trojan_O97M_Donoff_RPM_MTB{
	meta:
		description = "Trojan:O97M/Donoff.RPM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 72 67 75 6c 6b 66 6b 6c 22 29 29 61 64 69 61 67 2e 73 61 76 65 74 6f 66 69 6c 65 22 62 66 76 62 79 2e 76 62 73 22 2c 32 27 73 61 76 65 62 69 6e 61 72 79 64 61 74 61 74 6f 64 69 73 6b 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e } //00 00  ("https://pastebin.com/raw/rgulkfkl"))adiag.savetofile"bfvby.vbs",2'savebinarydatatodiskcreateobject("wscript.shell").run
	condition:
		any of ($a_*)
 
}