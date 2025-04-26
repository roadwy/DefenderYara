
rule TrojanDropper_O97M_Cerwm_A_MTB{
	meta:
		description = "TrojanDropper:O97M/Cerwm.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 64 65 63 6f 64 65 68 65 78 20 25 74 65 6d 70 25 5c } //1 Shell ("cmd /c certutil.exe -decodehex %temp%\
		$a_01_1 = {77 6d 69 63 20 70 61 74 68 20 77 69 6e 33 32 5f 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 25 74 65 6d 70 25 5c } //1 wmic path win32_process call create %temp%\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}