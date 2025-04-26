
rule TrojanDownloader_O97M_Qakbot_JAAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.JAAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 22 20 26 20 22 33 } //1 regsvr32.exe -e -n -i:" & RNum & " ..\Popol.ocx" & "3
		$a_01_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 22 20 26 20 22 34 } //1 regsvr32.exe -e -n -i:" & RNum & " ..\Popol.ocx" & "4
		$a_01_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 22 20 26 20 22 35 } //1 regsvr32.exe -e -n -i:" & RNum & " ..\Popol.ocx" & "5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}