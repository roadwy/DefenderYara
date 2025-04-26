
rule Trojan_Win32_Zusy_CB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 49 6f 61 67 38 39 77 67 6f 69 65 67 68 61 73 65 67 69 68 } //2 OIoag89wgoieghasegih
		$a_01_1 = {4f 49 6f 69 61 6a 66 67 39 38 61 6a 67 6f 69 61 6a 65 67 65 } //2 OIoiajfg98ajgoiajege
		$a_01_2 = {56 66 67 6f 69 61 65 66 67 69 6f 75 61 65 6f 67 69 61 68 65 6a 67 } //2 Vfgoiaefgiouaeogiahejg
		$a_01_3 = {62 76 41 45 47 4f 69 6f 61 68 67 69 61 73 68 65 67 } //2 bvAEGOioahgiasheg
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}