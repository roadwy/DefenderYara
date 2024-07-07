
rule Trojan_O97M_Netwire_RP_MTB{
	meta:
		description = "Trojan:O97M/Netwire.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 22 65 78 65 2e 51 46 52 2f 36 34 32 2e 34 39 31 2e 33 2e 32 39 31 2f 2f 3a 70 74 74 68 22 29 } //1 ("exe.QFR/642.491.3.291//:ptth")
		$a_01_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1  = CreateObject("WScript.Shell")
		$a_01_2 = {2e 52 75 6e 20 22 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 2b } //1 .Run "certutil.exe -urlcache -split -f " +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}