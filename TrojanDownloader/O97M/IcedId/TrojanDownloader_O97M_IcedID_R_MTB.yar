
rule TrojanDownloader_O97M_IcedID_R_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 } //5 = StrReverse(UserForm1.TextBox1)
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //5 CreateObject("wscript.shell")
		$a_01_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 65 63 69 66 66 4f 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 5c 52 45 53 55 5f 54 4e 45 52 52 55 43 5f 59 45 4b 48 22 29 } //1 = StrReverse("\eciffO\tfosorciM\erawtfoS\RESU_TNERRUC_YEKH")
		$a_01_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 4d 4f 42 56 73 73 65 63 63 41 5c 79 74 69 72 75 63 65 53 5c 64 72 6f 57 5c 22 29 } //1 = StrReverse("MOBVsseccA\ytiruceS\droW\")
		$a_01_4 = {20 3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 } //1  = "HKEY_CURRENT_USER\Software\Microsoft\Office\"
		$a_01_5 = {20 3d 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 } //1  = "\Word\Security\AccessVBOM"
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}