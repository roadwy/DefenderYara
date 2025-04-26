
rule Trojan_BAT_Agensla_GC_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 61 73 64 63 71 77 64 77 71 78 2e 67 71 2f 6c 69 76 65 72 70 6f 6f 6c 2d 66 63 2d 6e 65 77 73 2f 66 65 61 74 75 72 65 73 2f } //http://asdcqwdwqx.gq/liverpool-fc-news/features/  1
		$a_80_1 = {5b 53 50 4c 49 54 54 45 52 5d } //[SPLITTER]  1
		$a_80_2 = {55 73 65 72 41 67 65 6e 74 3a } //UserAgent:  1
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule Trojan_BAT_Agensla_GC_MTB_2{
	meta:
		description = "Trojan:BAT/Agensla.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * from Win32_ComputerSystem  1
		$a_80_1 = {56 69 72 74 75 61 6c 42 6f 78 } //VirtualBox  1
		$a_80_2 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  1
		$a_80_3 = {56 6d 77 61 72 65 } //Vmware  1
		$a_80_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //CreateObject("WScript.Shell").Run  1
		$a_80_5 = {53 23 74 61 72 74 75 70 } //S#tartup  1
		$a_80_6 = {53 6f 66 23 74 77 61 72 65 5c 4d 69 63 72 23 6f 73 6f 66 74 5c 57 69 6e 23 64 6f 77 73 5c 43 75 72 72 23 65 6e 74 56 65 72 23 73 69 6f 6e 5c 23 52 23 75 23 6e 5c } //Sof#tware\Micr#osoft\Win#dows\Curr#entVer#sion\#R#u#n\  1
		$a_80_7 = {41 6c 6c 6f 63 } //Alloc  1
		$a_80_8 = {57 72 69 74 65 } //Write  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}